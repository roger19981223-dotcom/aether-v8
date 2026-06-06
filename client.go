//go:build !js

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"
	utls "github.com/refraction-networking/utls"
)

const (
	NumStreams         = 6
	MSS                = 1350
	HeaderSize         = 30
	Magic              = 0x41455448
	AuthTokenSize      = 32
	PingFlag           = 0x0001
	AuthFlag           = 0x0002
	PongFlag           = 0x0004
	AdaptiveFECFlag    = 0x0008
	AetherALPN         = "aether/1"
	DialTimeout        = 15 * time.Second
	HandshakeTimeout   = 15 * time.Second
	MaxConcurrentConns = 2000
	VLESSListenAddr    = "0.0.0.0:11080"
	ClientCfgFile      = "aether_client.json"
	SafeMTUPayload     = 1350
	BlockAlignment     = 64
)

var (
	shardPool  = sync.Pool{New: func() interface{} { b := make([]byte, HeaderSize+MSS+1024); return &b }}
	framePool  = sync.Pool{New: func() interface{} { return make([]byte, 16384) }}
	outputPool = sync.Pool{New: func() interface{} { return make([]byte, 16*MSS+1024) }}
	randSeed   = uint32(time.Now().UnixNano())
	fecPool    sync.Map
)

func getEncoder(ds, ps int) reedsolomon.Encoder {
	if ds <= 0 {
		ds = 4
	}
	if ps <= 0 {
		ps = 1
	}
	key := (uint32(ds) << 16) | uint32(ps)
	if v, ok := fecPool.Load(key); ok {
		return v.(reedsolomon.Encoder)
	}
	enc, err := reedsolomon.New(ds, ps)
	if err == nil {
		fecPool.Store(key, enc)
		return enc
	}
	return nil
}

func fastRand() uint32 {
	val := atomic.AddUint32(&randSeed, 12345)
	val ^= val << 13
	val ^= val >> 17
	val ^= val << 5
	return val
}

func generateSmartPadding(payloadSize int) uint16 {
	targetSize := ((payloadSize / BlockAlignment) + 1) * BlockAlignment
	if targetSize > SafeMTUPayload {
		padding := SafeMTUPayload - payloadSize
		if padding < 0 {
			return 0
		}
		return uint16(padding)
	}
	return uint16(targetSize - payloadSize)
}

func GetShardPtr() *[]byte {
	bp := shardPool.Get().(*[]byte)
	*bp = (*bp)[:cap(*bp)]
	return bp
}

func PutShardPtr(bp *[]byte) {
	shardPool.Put(bp)
}

type TokenBucket struct {
	capacity  float64
	tokens    float64
	rate      float64
	lastToken time.Time
	mu        sync.Mutex
}

func NewTokenBucket(rate, capacity float64) *TokenBucket {
	return &TokenBucket{
		capacity:  capacity,
		tokens:    capacity,
		rate:      rate,
		lastToken: time.Now(),
	}
}

func (tb *TokenBucket) Wait(cost float64) {
	tb.mu.Lock()
	now := time.Now()
	if now.After(tb.lastToken) {
		elapsed := now.Sub(tb.lastToken).Seconds()
		tb.tokens += elapsed * tb.rate
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastToken = now
	}

	if tb.tokens >= cost {
		tb.tokens -= cost
		tb.mu.Unlock()
		return
	}

	deficit := cost - tb.tokens
	sleepDur := time.Duration((deficit / tb.rate) * float64(time.Second))
	tb.tokens = 0
	tb.lastToken = time.Now().Add(sleepDur)
	tb.mu.Unlock()
	time.Sleep(sleepDur)
}

func getAuthSecret(user, pass string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(user+":"+pass)))
}

func deriveToken(sec string, ts uint32) [32]byte {
	h := sha256.New()
	h.Write([]byte(sec))
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ts)
	h.Write(b)
	var t [32]byte
	copy(t[:], h.Sum(nil))
	return t
}

type PacketHeader struct {
	Magic      uint32
	ClientID   uint32
	SeqNo      uint32
	ShardIdx   uint16
	Flags      uint16
	PaddingLen uint16
	ChunkSize  uint32
	Timestamp  uint32
	Reserved   uint32
}

func (h *PacketHeader) EncodeTo(b []byte) {
	binary.BigEndian.PutUint32(b[0:4], h.Magic)
	binary.BigEndian.PutUint32(b[4:8], h.ClientID)
	binary.BigEndian.PutUint32(b[8:12], h.SeqNo)
	binary.BigEndian.PutUint16(b[12:14], h.ShardIdx)
	binary.BigEndian.PutUint16(b[14:16], h.Flags)
	binary.BigEndian.PutUint16(b[16:18], h.PaddingLen)
	binary.BigEndian.PutUint32(b[18:22], h.ChunkSize)
	binary.BigEndian.PutUint32(b[22:26], h.Timestamp)
	binary.BigEndian.PutUint32(b[26:30], h.Reserved)
}

func DecodeHeader(b []byte) *PacketHeader {
	return &PacketHeader{
		Magic:      binary.BigEndian.Uint32(b[0:4]),
		ClientID:   binary.BigEndian.Uint32(b[4:8]),
		SeqNo:      binary.BigEndian.Uint32(b[8:12]),
		ShardIdx:   binary.BigEndian.Uint16(b[12:14]),
		Flags:      binary.BigEndian.Uint16(b[14:16]),
		PaddingLen: binary.BigEndian.Uint16(b[16:18]),
		ChunkSize:  binary.BigEndian.Uint32(b[18:22]),
		Timestamp:  binary.BigEndian.Uint32(b[22:26]),
		Reserved:   binary.BigEndian.Uint32(b[26:30]),
	}
}

func (h *PacketHeader) GetFEC() (ds uint8, ps uint8) {
	if h.Flags&AdaptiveFECFlag != 0 {
		return uint8(h.Reserved >> 24), uint8((h.Reserved >> 16) & 0xFF)
	}
	return 4, 1
}

func (h *PacketHeader) SetFEC(ds uint8, ps uint8) {
	h.Flags |= AdaptiveFECFlag
	h.Reserved = (uint32(ds) << 24) | (uint32(ps) << 16) | (h.Reserved & 0xFFFF)
}

type parsedFrame struct {
	Type    byte
	ConnID  uint32
	Payload []byte
}

func parseFrames(buf *[]byte, d []byte) ([]parsedFrame, bool) {
	c := d
	if len(*buf) > 0 {
		c = append(*buf, d...)
	}
	if len(c) > 128<<10 {
		*buf = (*buf)[:0]
		return nil, false
	}
	var fs []parsedFrame
	o := 0
	for o+7 <= len(c) {
		t := c[o]
		id := binary.BigEndian.Uint32(c[o+1 : o+5])
		pl := int(binary.BigEndian.Uint16(c[o+5 : o+7]))
		if o+7+pl > len(c) {
			break
		}
		p := make([]byte, pl)
		copy(p, c[o+7:o+7+pl])
		fs = append(fs, parsedFrame{t, id, p})
		o += 7 + pl
	}
	if o < len(c) {
		tmp := make([]byte, len(c)-o)
		copy(tmp, c[o:])
		*buf = tmp
	} else {
		*buf = (*buf)[:0]
	}
	return fs, true
}

type TCPReassemblerEntry struct {
	shards    map[uint16]*[]byte
	chunkSize uint32
	received  int
	createdAt time.Time
	ds, ps    uint8
}

type decodedRecord struct {
	decodedAt time.Time
}

type TCPReassembler struct {
	mu              sync.Mutex
	windows         map[uint32]*TCPReassemblerEntry
	decoded         map[uint32]*decodedRecord
	outputCh        chan []byte
	clientID        uint32
	cleanupTicker   *time.Ticker
	stopCh          chan struct{}
	decodedTTL      time.Duration
	closeOnce       sync.Once
	nextExpectedSeq uint32
	readyBuffer     map[uint32][]byte
	lastAdvance     time.Time
}

func NewTCPReassembler(cid uint32, ttl time.Duration) *TCPReassembler {
	ar := &TCPReassembler{
		windows:     make(map[uint32]*TCPReassemblerEntry),
		decoded:     make(map[uint32]*decodedRecord),
		outputCh:    make(chan []byte, 16384), // 进一步扩大缓冲抗高并发毛刺
		clientID:    cid,
		stopCh:      make(chan struct{}),
		decodedTTL:  ttl,
		readyBuffer: make(map[uint32][]byte),
		lastAdvance: time.Now(),
	}
	ar.cleanupTicker = time.NewTicker(ttl / 2)
	go ar.cleanupLoop()
	return ar
}

func (ar *TCPReassembler) AddShard(seqNo uint32, shardIdx uint16, chunkSize uint32, dataPtr *[]byte, ds, ps uint8) {
	ar.mu.Lock()
	if int32(seqNo-ar.nextExpectedSeq) < 0 || ar.decoded[seqNo] != nil {
		ar.mu.Unlock()
		PutShardPtr(dataPtr)
		return
	}
	if ds == 0 {
		ds, ps = 4, 1
	}
	e, ok := ar.windows[seqNo]
	if !ok {
		e = &TCPReassemblerEntry{
			shards:    make(map[uint16]*[]byte),
			chunkSize: chunkSize,
			createdAt: time.Now(),
			ds:        ds,
			ps:        ps,
		}
		ar.windows[seqNo] = e
	}
	if _, dup := e.shards[shardIdx]; dup {
		ar.mu.Unlock()
		PutShardPtr(dataPtr)
		return
	}
	e.shards[shardIdx] = dataPtr
	e.received++
	var shardsClone map[uint16]*[]byte
	triggerDecode := e.received >= int(e.ds)
	if triggerDecode {
		shardsClone = make(map[uint16]*[]byte)
		for k, v := range e.shards {
			shardsClone[k] = v
		}
		delete(ar.windows, seqNo)
	}
	ar.mu.Unlock()
	if triggerDecode {
		if res := ar.decodeOutsideLock(chunkSize, shardsClone, e.ds, e.ps); res != nil {
			ar.commitDecodedAndSend(seqNo, res)
		} else {
			ar.mu.Lock()
			ar.decoded[seqNo] = &decodedRecord{decodedAt: time.Now()}
			ar.readyBuffer[seqNo] = nil
			ar.drainReady()
			ar.mu.Unlock()
		}
	}
}

func (ar *TCPReassembler) commitDecodedAndSend(seqNo uint32, data []byte) {
	ar.mu.Lock()
	ar.decoded[seqNo] = &decodedRecord{decodedAt: time.Now()}
	ar.readyBuffer[seqNo] = data
	ar.drainReady()
	ar.mu.Unlock()
}

func (ar *TCPReassembler) decodeOutsideLock(chunkSize uint32, shardsClone map[uint16]*[]byte, ds, ps uint8) []byte {
	defer func() {
		for _, sp := range shardsClone {
			if sp != nil {
				PutShardPtr(sp)
			}
		}
	}()
	if chunkSize == 0 || uint64(chunkSize) > uint64(int(ds)*MSS) {
		return nil
	}
	enc := getEncoder(int(ds), int(ps))
	if enc == nil {
		return nil
	}
	ss := int((uint64(chunkSize) + uint64(ds) - 1) / uint64(ds))
	total := int(ds) + int(ps)
	matrix := make([][]byte, total)
	for i, dp := range shardsClone {
		if int(i) < total && dp != nil {
			matrix[i] = (*dp)[HeaderSize : HeaderSize+ss]
		}
	}
	if err := enc.Reconstruct(matrix); err != nil {
		return nil
	}
	res := outputPool.Get().([]byte)[:0]
	for i := 0; i < int(ds); i++ {
		if matrix[i] != nil {
			res = append(res, matrix[i]...)
		}
	}
	if len(res) > int(chunkSize) {
		res = res[:chunkSize]
	}
	return res
}

func (ar *TCPReassembler) drainReady() {
	for {
		payload, exists := ar.readyBuffer[ar.nextExpectedSeq]
		if !exists {
			break
		}

		if payload != nil {
			select {
			case ar.outputCh <- payload:
			case <-ar.stopCh:
				return
			default:
				log.Printf("[WARN] outputCh full, dropping seq %d", ar.nextExpectedSeq)
			}
		} else {
			log.Printf("[FEC] skip nil seq %d (decode failed)", ar.nextExpectedSeq)
		}

		delete(ar.readyBuffer, ar.nextExpectedSeq)
		ar.nextExpectedSeq++
		ar.lastAdvance = time.Now()
	}

	for s := range ar.readyBuffer {
		if int32(s-ar.nextExpectedSeq) < 0 {
			delete(ar.readyBuffer, s)
		}
	}
}

func (ar *TCPReassembler) Output() <-chan []byte {
	return ar.outputCh
}

func (ar *TCPReassembler) cleanupLoop() {
	for {
		select {
		case <-ar.stopCh:
			return
		case <-ar.cleanupTicker.C:
			ar.cleanupStale()
		}
	}
}

func (ar *TCPReassembler) cleanupStale() {
	ar.mu.Lock()
	n := time.Now()
	// 核心修复 2：与服务端同步，断流 3 秒立刻强制重启引擎，实现无缝丝滑自愈
	if len(ar.readyBuffer) > 0 && n.Sub(ar.lastAdvance) > 3*time.Second {
		ar.mu.Unlock()
		ar.Close()
		return
	}
	for k, r := range ar.decoded {
		if n.Sub(r.decodedAt) > ar.decodedTTL && int32(k-ar.nextExpectedSeq) < 0 {
			delete(ar.decoded, k)
		}
	}
	for k, e := range ar.windows {
		if n.Sub(e.createdAt) > ar.decodedTTL {
			for _, sp := range e.shards {
				if sp != nil {
					PutShardPtr(sp)
				}
			}
			delete(ar.windows, k)
		}
	}
	ar.mu.Unlock()
}

func (ar *TCPReassembler) Close() {
	ar.closeOnce.Do(func() {
		ar.cleanupTicker.Stop()
		close(ar.stopCh)
		close(ar.outputCh)
	})
}

type SafeStream struct {
	conn      net.Conn
	mu        sync.Mutex
	closed    atomic.Bool
	srtt      atomic.Int64
	rttVar    atomic.Int64
	lossCount atomic.Uint32
	pingCh    chan struct{}
}

func (s *SafeStream) Write(b []byte) (int, error) {
	if s.closed.Load() {
		return 0, io.EOF
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	defer s.conn.SetWriteDeadline(time.Time{})
	n, err := s.conn.Write(b)
	if err != nil {
		s.Close()
	}
	return n, err
}

func (s *SafeStream) Close() {
	if s.closed.CompareAndSwap(false, true) {
		s.conn.Close()
		close(s.pingCh)
	}
}

func (s *SafeStream) IsClosed() bool {
	return s.closed.Load()
}

func (s *SafeStream) UpdateRTT(m int64) {
	sr := s.srtt.Load()
	if sr == 0 {
		s.srtt.Store(m)
		s.rttVar.Store(m / 2)
		return
	}
	v := s.rttVar.Load()
	diff := m - sr
	if diff < 0 {
		diff = -diff
	}
	s.rttVar.Store((3*v + diff) / 4)
	s.srtt.Store((7*sr + m) / 8)
}

type ProxyConn struct {
	connID       uint32
	conn         net.Conn
	cl           atomic.Bool
	connectAckCh chan struct{}
	connectErrCh chan struct{}
	wc           chan []byte
	done         chan struct{}
	closeOnce    sync.Once
}

type AdaptiveDispatcher struct {
	node       NodeConfig
	clientID   uint32
	streams    []*SafeStream
	sMu        sync.RWMutex
	tr         *TCPReassembler
	pfb        []byte
	fw         atomic.Uint32
	conns      sync.Map
	stopCh     chan struct{}
	pacing     *TokenBucket
	currentDS  uint8
	currentPS  uint8
	sdm        sync.RWMutex
	muxWriteMu sync.Mutex
}

func NewAdaptiveDispatcher(n NodeConfig) *AdaptiveDispatcher {
	cid := fastRand()
	ad := &AdaptiveDispatcher{
		node:      n,
		clientID:  cid,
		streams:   make([]*SafeStream, NumStreams),
		tr:        NewTCPReassembler(cid, 30*time.Second),
		stopCh:    make(chan struct{}),
		pacing:    NewTokenBucket(12500000, 1048576),
		currentDS: 4,
		currentPS: 1,
	}
	go ad.monitorHealth()
	go ad.handleReassembler()
	return ad
}

func (c *AdaptiveDispatcher) reboot() {
	log.Printf("[CLI] 🔴 引擎长时间停滞或数据流严重损坏，执行安全热重启...")
	c.Close()
	go func() {
		time.Sleep(500 * time.Millisecond)
		applyEngine()
	}()
}

func (c *AdaptiveDispatcher) Close() {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	c.sMu.Lock()
	for i, st := range c.streams {
		if st != nil {
			st.Close()
			c.streams[i] = nil
		}
	}
	c.sMu.Unlock()
	c.tr.Close()
	c.conns.Range(func(k, v interface{}) bool {
		pc := v.(*ProxyConn)
		pc.cl.Store(true)
		pc.conn.Close()
		c.conns.Delete(k)
		return true
	})
}

func TuneTCPConn(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(4 << 20)
		tc.SetWriteBuffer(4 << 20)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(15 * time.Second)
	}
}

func (c *AdaptiveDispatcher) getTlsConfig() *utls.Config {
	sni := c.node.SNI
	if sni == "" {
		host, _, err := net.SplitHostPort(c.node.Server)
		if err == nil {
			sni = host
		} else {
			sni = c.node.Server
		}
	}
	return &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{AetherALPN, "h2", "http/1.1"},
	}
}

func (c *AdaptiveDispatcher) dialStream() *SafeStream {
	rc, err := net.DialTimeout("tcp", c.node.Server, DialTimeout)
	if err != nil {
		return nil
	}
	TuneTCPConn(rc)
	uc := utls.UClient(rc, c.getTlsConfig(), utls.HelloChrome_Auto)
	uc.SetDeadline(time.Now().Add(HandshakeTimeout))
	if err := uc.Handshake(); err != nil {
		uc.Close()
		return nil
	}
	uc.SetDeadline(time.Time{})
	st := &SafeStream{conn: uc, pingCh: make(chan struct{}, 1)}
	pl := generateSmartPadding(HeaderSize + AuthTokenSize)

	ts := uint32(time.Now().UnixMilli() & 0xFFFFFFFF)
	tk := deriveToken(getAuthSecret(c.node.Username, c.node.Password), ts)

	h := &PacketHeader{
		Magic:      Magic,
		ClientID:   c.clientID,
		SeqNo:      fastRand(),
		Flags:      AuthFlag,
		PaddingLen: pl,
		ChunkSize:  AuthTokenSize,
		Timestamp:  ts,
	}
	c.sdm.RLock()
	h.SetFEC(c.currentDS, c.currentPS)
	c.sdm.RUnlock()

	b := make([]byte, HeaderSize+AuthTokenSize+int(pl))
	h.EncodeTo(b[:HeaderSize])
	copy(b[HeaderSize:HeaderSize+AuthTokenSize], tk[:])
	st.Write(b)
	go c.streamReadLoop(st)
	return st
}

func (c *AdaptiveDispatcher) streamReadLoop(st *SafeStream) {
	hb := make([]byte, HeaderSize)
	for {
		st.conn.SetReadDeadline(time.Now().Add(45 * time.Second))
		if _, e := io.ReadFull(st.conn, hb); e != nil {
			st.Close()
			return
		}
		h := DecodeHeader(hb)
		if h.Magic != Magic {
			st.Close()
			return
		}
		ds, ps := h.GetFEC()
		if ds > 0 && ps > 0 {
			c.sdm.Lock()
			c.currentDS = ds
			c.currentPS = ps
			c.sdm.Unlock()
		}
		ss := int((h.ChunkSize + uint32(ds) - 1) / uint32(ds))
		tl := uint32(ss) + uint32(h.PaddingLen)
		
		var bp *[]byte
		if tl > 0 {
			bp = GetShardPtr()
			if _, e := io.ReadFull(st.conn, (*bp)[HeaderSize:HeaderSize+int(tl)]); e != nil {
				PutShardPtr(bp)
				st.Close()
				return
			}
		}
		
		if h.Flags&PingFlag != 0 {
			pl := generateSmartPadding(HeaderSize)
			p := &PacketHeader{Magic: Magic, ClientID: c.clientID, Flags: PongFlag, Timestamp: h.Timestamp, PaddingLen: pl}
			c.sdm.RLock()
			p.SetFEC(c.currentDS, c.currentPS)
			c.sdm.RUnlock()
			
			bo := make([]byte, HeaderSize+int(pl))
			p.EncodeTo(bo[:HeaderSize])
			
			if _, err := st.Write(bo); err != nil {
				st.Close()
			}
			
			if bp != nil {
				PutShardPtr(bp)
			}
			continue
		}
		if h.Flags&PongFlag != 0 {
			m := time.Now().UnixMilli() - int64(h.Timestamp)
			if m > 0 && m < 5000 {
				st.UpdateRTT(m)
			}
			if bp != nil {
				PutShardPtr(bp)
			}
			select {
			case st.pingCh <- struct{}{}:
			default:
			}
			continue
		}
		if bp != nil {
			*bp = (*bp)[:HeaderSize+ss]
			c.tr.AddShard(h.SeqNo, h.ShardIdx, h.ChunkSize, bp, ds, ps)
		}
	}
}

func (c *AdaptiveDispatcher) monitorHealth() {
	tk := time.NewTicker(3 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-tk.C:
			var wg sync.WaitGroup
			var activeCount int32
			var avgRTT int64
			var lossCount uint32

			for i := 0; i < NumStreams; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					c.sMu.RLock()
					st := c.streams[idx]
					c.sMu.RUnlock()

					if st == nil || st.IsClosed() {
						atomic.AddUint32(&lossCount, 1)
						newSt := c.dialStream()
						if newSt != nil {
							c.sMu.Lock()
							c.streams[idx] = newSt
							c.sMu.Unlock()
							atomic.AddInt32(&activeCount, 1)
						}
					} else {
						atomic.AddInt32(&activeCount, 1)
						atomic.AddInt64(&avgRTT, st.srtt.Load())

						pl := generateSmartPadding(HeaderSize)
						ts := uint32(time.Now().UnixMilli() & 0xFFFFFFFF)
						h := &PacketHeader{Magic: Magic, ClientID: c.clientID, Flags: PingFlag, Timestamp: ts, PaddingLen: pl}
						c.sdm.RLock()
						h.SetFEC(c.currentDS, c.currentPS)
						c.sdm.RUnlock()
						
						b := make([]byte, HeaderSize+int(pl))
						h.EncodeTo(b[:HeaderSize])
						
						if _, err := st.Write(b); err != nil {
							st.Close()
						}

						tc := time.NewTimer(3 * time.Second)
						select {
						case <-st.pingCh:
							tc.Stop()
							st.lossCount.Store(0)
						case <-tc.C:
							st.lossCount.Add(1)
							if st.lossCount.Load() > 2 {
								st.Close()
							}
						}
					}
				}(i)
			}
			wg.Wait()

			if activeCount > 0 {
				avgRTT /= int64(activeCount)
			}
			lossRate := float64(lossCount) / float64(NumStreams)
			c.sdm.Lock()
			if lossRate > 0.15 {
				c.currentDS, c.currentPS = 4, 2
			} else if avgRTT > 0 && avgRTT < 100 && lossRate < 0.02 {
				c.currentDS, c.currentPS = 10, 1
			} else {
				c.currentDS, c.currentPS = 4, 1
			}
			c.sdm.Unlock()
		}
	}
}

func (c *AdaptiveDispatcher) handleReassembler() {
	for {
		select {
		case <-c.stopCh:
			return
		case <-c.tr.stopCh:
			c.reboot()
			return
		case d, ok := <-c.tr.Output():
			if !ok {
				return
			}
			frames, ok := parseFrames(&c.pfb, d)
			if !ok {
				outputPool.Put(d[:cap(d)])
				c.reboot()
				return
			}
			for _, f := range frames {
				if pc, ok := c.conns.Load(f.ConnID); ok {
					pc2 := pc.(*ProxyConn)
					if f.Type == 1 {
						select {
						case pc2.connectAckCh <- struct{}{}:
						default:
						}
					} else if f.Type == 4 || f.Type == 5 {
						if !pc2.cl.Load() {
							select {
							case pc2.wc <- f.Payload:
							default:
								pc2.cl.Store(true)
								pc2.conn.Close()
							}
						}
					} else if f.Type == 2 || f.Type == 3 {
						select {
						case pc2.connectErrCh <- struct{}{}:
						default:
						}
						pc2.cl.Store(true)
						pc2.conn.Close()
						c.conns.Delete(f.ConnID)
					}
				}
			}
			outputPool.Put(d[:cap(d)])
		}
	}
}

type streamStat struct {
	st  *SafeStream
	rtt int64
}

func (c *AdaptiveDispatcher) SendChunk(data []byte) {
	if len(data) == 0 {
		return
	}
	
	c.pacing.Wait(float64(len(data)))

	c.muxWriteMu.Lock()
	defer c.muxWriteMu.Unlock()

	o := 0
	var noStreamSince time.Time
	for o < len(data) {
		c.sMu.RLock()
		var stats []streamStat
		for _, st := range c.streams {
			if st != nil && !st.IsClosed() {
				stats = append(stats, streamStat{st, st.srtt.Load()})
			}
		}
		c.sMu.RUnlock()
		if len(stats) == 0 {
			if noStreamSince.IsZero() {
				noStreamSince = time.Now()
			}
			if time.Since(noStreamSince) > 10*time.Second {
				log.Printf("[CLI] no active tunnel streams; dropping %d bytes after wait", len(data)-o)
				return
			}
			select {
			case <-c.stopCh:
				return
			case <-time.After(20 * time.Millisecond):
			}
			continue
		}
		noStreamSince = time.Time{}
		sort.Slice(stats, func(i, j int) bool { return stats[i].rtt < stats[j].rtt })

		c.sdm.RLock()
		ds, ps := int(c.currentDS), int(c.currentPS)
		c.sdm.RUnlock()

		enc := getEncoder(ds, ps)
		if enc == nil {
			return
		}
		sq := c.fw.Add(1) - 1
		total := ds + ps
		e := o + ds*MSS
		if e > len(data) {
			e = len(data)
		}
		ch := data[o:e]
		cs := uint32(len(ch))
		ss := int((cs + uint32(ds) - 1) / uint32(ds))
		if ss > MSS {
			ss = MSS
		}
		
		sh := make([][]byte, total)
		buffers := make([][]byte, total)
		
		for i := 0; i < total; i++ {
			maxPktLen := HeaderSize + ss + SafeMTUPayload
			buf := make([]byte, maxPktLen)
			buffers[i] = buf
			sh[i] = buf[HeaderSize : HeaderSize+ss]
			
			if i < ds {
				st, en := i*ss, i*ss+ss
				if st < int(cs) {
					if en > int(cs) {
						en = int(cs)
					}
					copy(sh[i], ch[st:en])
				}
			}
		}

		if err := enc.Encode(sh); err != nil {
			return
		}
		
		ts := uint32(time.Now().UnixMilli() & 0xFFFFFFFF)
		for i := 0; i < total; i++ {
			st := stats[i%len(stats)].st
			actualChunkSize := HeaderSize + len(sh[i])
			pl := generateSmartPadding(actualChunkSize)
			
			h := &PacketHeader{Magic: Magic, ClientID: c.clientID, SeqNo: sq, ShardIdx: uint16(i), PaddingLen: pl, ChunkSize: cs, Timestamp: ts}
			h.SetFEC(uint8(ds), uint8(ps))
			
			buf := buffers[i]
			h.EncodeTo(buf[:HeaderSize])
			
			pe := HeaderSize + len(sh[i])
			for j := pe; j < pe+int(pl); j++ {
				buf[j] = 0
			}
			
			pkt := buf[:pe+int(pl)]
			if _, err := st.Write(pkt); err != nil {
			}
		}
		o = e
	}
}

func (c *AdaptiveDispatcher) DialProxy(conn net.Conn) {
	pc := &ProxyConn{
		connID:       fastRand(),
		conn:         conn,
		connectAckCh: make(chan struct{}, 1),
		connectErrCh: make(chan struct{}, 1),
		wc:           make(chan []byte, 1024),
		done:         make(chan struct{}),
	}
	c.conns.Store(pc.connID, pc)

	go func() {
		defer func() {
			pc.cl.Store(true)
			pc.closeOnce.Do(func() { close(pc.done) })
			conn.Close()
			c.conns.Delete(pc.connID)

			fb := framePool.Get().([]byte)
			fb = fb[:7]
			fb[0] = 0x03
			binary.BigEndian.PutUint32(fb[1:5], pc.connID)
			binary.BigEndian.PutUint16(fb[5:7], 0)
			c.SendChunk(fb)
			framePool.Put(fb[:cap(fb)])
		}()

		conn.SetReadDeadline(time.Now().Add(10 * time.Second))

		ver := make([]byte, 1)
		if _, err := io.ReadFull(conn, ver); err != nil {
			return
		}
		if ver[0] != 0 {
			log.Printf("[CLI] 致命: 收到非 VLESS 流量 (首字节: 0x%02x)，请检查软路由是否关掉了 TLS", ver[0])
			return
		}

		uuid := make([]byte, 16)
		if _, err := io.ReadFull(conn, uuid); err != nil {
			return
		}

		addonLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, addonLenBuf); err != nil {
			return
		}
		addonLen := int(addonLenBuf[0])
		if addonLen > 0 {
			addon := make([]byte, addonLen)
			if _, err := io.ReadFull(conn, addon); err != nil {
				return
			}
		}

		cmdBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, cmdBuf); err != nil {
			return
		}
		cmd := cmdBuf[0]
		if cmd == 3 {
			// 核心修复机制 3：封杀本地拨号陷阱，硬拦截多路复用请求
			log.Printf("===============================================================")
			log.Printf("[CLI] 🛑 致命错误: 拦截到了 V2Ray Mux (多路复用) 请求！")
			log.Printf("[CLI] 🛑 原因解释: 上个版本尝试在本地解析 MUX，导致你的流量没有过墙就被本地直连发出了！")
			log.Printf("[CLI] 🛑 解决方案: 请立即前往 PassWall -> 节点设置 -> 关闭【Mux】(多路复用) 功能！")
			log.Printf("[CLI] 🛑 Aether 引擎底层已自带并发多路物理隧道，嵌套 Mux 会直接导致断网！")
			log.Printf("===============================================================")
			return
		}
		if cmd != 1 {
			log.Printf("[CLI] 警告: 拦截了非 TCP 请求 (CMD=%d)", cmd)
			return
		}

		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBuf); err != nil {
			return
		}

		atypBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, atypBuf); err != nil {
			return
		}
		atyp := atypBuf[0]

		var addr string
		
		switch atyp {
		case 0x01: // IPv4
			ip := make([]byte, 4)
			if _, err := io.ReadFull(conn, ip); err != nil {
				return
			}
			addr = net.IP(ip).String()
		case 0x02: // 官方规范: VLESS 域名 
			lenBuf := make([]byte, 1)
			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				return
			}
			domainLen := int(lenBuf[0])
			domainBuf := make([]byte, domainLen)
			if _, err := io.ReadFull(conn, domainBuf); err != nil {
				return
			}
			addr = string(domainBuf)
		case 0x03: // 变体兼容: SOCKS5 误传域名类型
			lenBuf := make([]byte, 1)
			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				return
			}
			domainLen := int(lenBuf[0])
			domainBuf := make([]byte, domainLen)
			if _, err := io.ReadFull(conn, domainBuf); err != nil {
				return
			}
			addr = string(domainBuf)
		case 0x04: // IPv6
			ip := make([]byte, 16)
			if _, err := io.ReadFull(conn, ip); err != nil {
				return
			}
			addr = net.IP(ip).String()
		default:
			log.Printf("[CLI] 致命: 未知的 VLESS ATYP: 0x%02x", atyp)
			return
		}

		conn.SetReadDeadline(time.Time{})
        
		targetPort := binary.BigEndian.Uint16(portBuf)

		// 核心防护：防透明代理回环 (Routing Loop)
		serverHost, _, err := net.SplitHostPort(c.node.Server)
		if err != nil || serverHost == "" {
			serverHost = c.node.Server
		}
		
		isLoop := false
		if addr == serverHost {
			isLoop = true
		} else {
			if ips, err := net.LookupIP(serverHost); err == nil {
				for _, ip := range ips {
					if addr == ip.String() {
						isLoop = true
						break
					}
				}
			}
		}

		if isLoop {
			log.Printf("===============================================================")
			log.Printf("[CLI] 🛑 致命错误: 拦截到发往代理服务器自身 (%s) 的流量！", addr)
			log.Printf("[CLI] 🛑 原因解释: 软路由(PassWall)把 Aether 客户端的底层出站流量也给劫持了，形成了无限死循环！")
			log.Printf("[CLI] 🛑 解决方案: 请前往 PassWall -> 规则管理 -> 直连 IP 列表，将服务器 IP [%s] 添加进去！", addr)
			log.Printf("===============================================================")
			return
		}

		addrLen := len(addr)
		log.Printf("[CLI] 建立通道 -> %s:%d", addr, targetPort)
		reqLen := 1 + addrLen + 2
		connPayload := make([]byte, reqLen)
		connPayload[0] = byte(addrLen)
		copy(connPayload[1:1+addrLen], addr)
		copy(connPayload[1+addrLen:], portBuf)

		fb := framePool.Get().([]byte)
		frameLen := 7 + reqLen
		if cap(fb) < frameLen {
			fb = make([]byte, frameLen)
		}
		fb = fb[:frameLen]
		fb[0] = 0x01
		binary.BigEndian.PutUint32(fb[1:5], pc.connID)
		binary.BigEndian.PutUint16(fb[5:7], uint16(reqLen))
		copy(fb[7:], connPayload)
		c.SendChunk(fb)
		framePool.Put(fb[:cap(fb)])

		select {
		case <-pc.connectAckCh:
		case <-pc.connectErrCh:
			log.Printf("[CLI] 拒绝: 服务端拒绝代理或目标连接失败 -> %s", addr)
			return
		case <-pc.done:
			return
		case <-time.After(35 * time.Second):
			log.Printf("[CLI] 超时: 等待服务端响应超时 -> %s (请检查服务端控制台输出)", addr)
			return
		}

		conn.Write([]byte{0x00, 0x00})

		go func() {
			for {
				select {
				case <-pc.done:
					return
				case p, ok := <-pc.wc:
					if !ok {
						return
					}
					pc.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
					if _, err := pc.conn.Write(p); err != nil {
						return
					}
					pc.conn.SetWriteDeadline(time.Time{})
				}
			}
		}()

		buf := make([]byte, 32768)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				df := framePool.Get().([]byte)
				dfLen := 7 + n
				if cap(df) < dfLen {
					df = make([]byte, dfLen)
				}
				df = df[:dfLen]
				df[0] = 0x02
				binary.BigEndian.PutUint32(df[1:5], pc.connID)
				binary.BigEndian.PutUint16(df[5:7], uint16(n))
				copy(df[7:], buf[:n])
				c.SendChunk(df)
				framePool.Put(df[:cap(df)])
			}
			if err != nil {
				return
			}
		}
	}()
}

type NodeConfig struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Server   string `json:"server"`
	Username string `json:"username"`
	Password string `json:"password"`
	SNI      string `json:"sni"`
}

type AppConfig struct {
	Enable       bool         `json:"enable"`
	ActiveNodeID string       `json:"active_node_id"`
	Nodes        []NodeConfig `json:"nodes"`
}

var (
	globalConfig AppConfig
	configMu     sync.RWMutex
	currentDisp  *AdaptiveDispatcher
	dispMu       sync.Mutex
	vlessLN      net.Listener
)

func initConfig() {
	globalConfig = AppConfig{
		Enable:       false,
		ActiveNodeID: "",
		Nodes:        []NodeConfig{},
	}
	if b, e := os.ReadFile(ClientCfgFile); e == nil {
		json.Unmarshal(b, &globalConfig)
	}
}

func saveConfig() {
	configMu.RLock()
	b, _ := json.MarshalIndent(globalConfig, "", "  ")
	configMu.RUnlock()
	os.WriteFile(ClientCfgFile, b, 0644)
}

func applyEngine() {
	dispMu.Lock()
	defer dispMu.Unlock()
	if currentDisp != nil {
		currentDisp.Close()
		currentDisp = nil
	}
	if vlessLN != nil {
		vlessLN.Close()
		vlessLN = nil
	}
	configMu.RLock()
	en := globalConfig.Enable
	nid := globalConfig.ActiveNodeID
	var actNode *NodeConfig
	for _, n := range globalConfig.Nodes {
		if n.ID == nid {
			actNode = &n
			break
		}
	}
	configMu.RUnlock()
	if !en || actNode == nil {
		return
	}
	currentDisp = NewAdaptiveDispatcher(*actNode)
	ln, err := net.Listen("tcp", VLESSListenAddr)
	if err != nil {
		return
	}
	vlessLN = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dispMu.Lock()
			d := currentDisp
			dispMu.Unlock()
			if d != nil {
				d.DialProxy(c)
			} else {
				c.Close()
			}
		}
	}()
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		configMu.RLock()
		dispMu.Lock()
		rn := currentDisp != nil
		dispMu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"running": rn,
			"conf":    globalConfig,
		})
		configMu.RUnlock()
	} else if r.Method == "POST" {
		var nc AppConfig
		json.NewDecoder(r.Body).Decode(&nc)
		configMu.Lock()
		globalConfig = nc
		configMu.Unlock()
		saveConfig()
		applyEngine()
		w.Write([]byte(`{"ok":true}`))
	}
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	initConfig()
	applyEngine()
	http.HandleFunc("/api", handleAPI)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(clientHTML))
	})
	http.ListenAndServe("0.0.0.0:9999", nil)
}

const clientHTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Aether Client</title><script src="https://cdn.tailwindcss.com"></script><script src="https://unpkg.com/vue@3/dist/vue.global.prod.js"></script><style>body{background-color:#f9fafb;color:#111827;font-family:system-ui,-apple-system,sans-serif}</style></head><body><div id="app" class="max-w-4xl mx-auto p-6 mt-10"><div class="flex justify-between items-end mb-8"><div><h1 class="text-4xl font-black tracking-tight mb-2">Aether<span class="text-blue-500">.</span>Client</h1><p class="text-gray-500 font-medium">Enterprise Edition Gateway</p></div><div class="text-right"><div class="text-sm font-bold text-gray-400 mb-2">本地监听</div><div class="text-xl font-mono text-gray-800 bg-white px-4 py-2 rounded shadow-sm border border-gray-100">VLESS 127.0.0.1:11080</div></div></div><div class="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden mb-8"><div class="p-8 flex items-center justify-between border-b border-gray-50"><div class="flex items-center gap-6"><div class="relative"><div class="w-20 h-20 rounded-full flex items-center justify-center transition-colors duration-500" :class="r?'bg-blue-100':'bg-gray-100'"><div class="w-16 h-16 rounded-full flex items-center justify-center text-3xl transition-colors duration-500" :class="r?'bg-blue-500 text-white shadow-lg shadow-blue-500/40':'bg-gray-300 text-gray-500'">⚡</div></div><div v-if="r" class="absolute top-0 right-0 w-5 h-5 bg-green-500 border-4 border-white rounded-full"></div></div><div><h2 class="text-2xl font-bold tracking-tight mb-1">核心引擎引擎状态</h2><p class="text-gray-500 font-medium text-sm">控制全链路加速与混淆</p></div></div><button @click="toggleEngine" :class="r?'bg-red-500 hover:bg-red-600 shadow-red-500/30':'bg-black hover:bg-gray-800 shadow-gray-900/30'" class="px-8 py-4 rounded-xl text-white font-black tracking-widest transition-all shadow-lg">{{r?'断开连接 STOP':'启动引擎 START'}}</button></div></div><div class="flex justify-between items-center mb-6"><h2 class="text-2xl font-bold tracking-tight">节点池配置</h2><button @click="openNodeModal(null)" class="bg-gray-900 text-white px-5 py-2.5 rounded-lg font-bold shadow hover:bg-gray-700 transition">+ 导入节点</button></div><div class="grid grid-cols-1 md:grid-cols-2 gap-4"><div v-for="n in c.nodes" class="bg-white rounded-xl p-5 shadow-sm border transition cursor-pointer hover:border-blue-300 relative overflow-hidden" :class="c.active_node_id===n.id?'border-blue-500 ring-2 ring-blue-500/20':'border-gray-200'" @click="c.active_node_id=n.id;saveConfig()"><div v-if="c.active_node_id===n.id" class="absolute top-0 right-0 bg-blue-500 text-white text-xs font-bold px-3 py-1 rounded-bl-lg">当前使用</div><h3 class="font-bold text-lg mb-1 truncate pr-16">{{n.name}}</h3><p class="text-gray-500 font-mono text-xs mb-4">{{n.server}}</p><div class="flex gap-2"><button @click.stop="openNodeModal(n)" class="bg-gray-100 hover:bg-gray-200 text-gray-700 px-3 py-1.5 rounded text-sm font-bold transition flex-1">配置</button><button @click.stop="copyLink()" class="bg-gray-100 hover:bg-gray-200 text-gray-700 px-3 py-1.5 rounded text-sm font-bold transition flex-1">导出</button><button @click.stop="delNode(n.id)" class="bg-red-50 hover:bg-red-100 text-red-600 px-3 py-1.5 rounded text-sm font-bold transition flex-1">删除</button></div></div><div v-if="c.nodes.length===0" class="col-span-full bg-gray-50 border-2 border-dashed border-gray-200 rounded-xl p-12 text-center text-gray-400 font-bold">目前还没有配置任何节点，点击右上角导入。</div></div><div v-if="showModal" class="fixed inset-0 bg-gray-900/40 backdrop-blur-sm flex items-center justify-center z-50"><div class="bg-white p-8 rounded-2xl w-[480px] shadow-2xl border border-gray-100"><h3 class="text-2xl font-bold mb-6">{{isEdit?'编辑节点参数':'导入新节点'}}</h3><div class="space-y-4"><div><label class="block text-sm font-bold text-gray-500 mb-1">别名</label><input v-model="editNode.name" class="w-full p-3 bg-gray-50 border border-gray-200 rounded-lg outline-none focus:border-blue-500 transition"></div><div><label class="block text-sm font-bold text-gray-500 mb-1">服务器 IP:端口</label><input v-model="editNode.server" class="w-full p-3 bg-gray-50 border border-gray-200 rounded-lg outline-none focus:border-blue-500 transition font-mono"></div><div class="grid grid-cols-2 gap-4"><div><label class="block text-sm font-bold text-gray-500 mb-1">用户名</label><input v-model="editNode.username" class="w-full p-3 bg-gray-50 border border-gray-200 rounded-lg outline-none focus:border-blue-500 transition"></div><div><label class="block text-sm font-bold text-gray-500 mb-1">鉴权密钥</label><input v-model="editNode.password" class="w-full p-3 bg-gray-50 border border-gray-200 rounded-lg outline-none focus:border-blue-500 transition"></div></div><div><label class="block text-sm font-bold text-gray-500 mb-1">伪装域名 (SNI)</label><input v-model="editNode.sni" class="w-full p-3 bg-gray-50 border border-gray-200 rounded-lg outline-none focus:border-blue-500 transition font-mono" placeholder="www.microsoft.com"></div><div class="flex gap-4 mt-8"><button @click="saveNode" class="flex-1 bg-black text-white p-3 rounded-lg font-bold shadow hover:bg-gray-800 transition">保存配置</button><button @click="showModal=false" class="flex-1 bg-gray-100 text-gray-600 p-3 rounded-lg font-bold hover:bg-gray-200 transition">取消</button></div></div></div></div></div><script>Vue.createApp({data(){return{r:false,c:{enable:false,active_node_id:'',nodes:[]},showModal:false,isEdit:false,editNode:{}}},methods:{copyLink(){let u='vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:11080?encryption=none&security=none&type=tcp&headerType=none#Aether-Local';let e=document.createElement('textarea');e.value=u;document.body.appendChild(e);e.select();document.execCommand('copy');document.body.removeChild(e);alert('本地 VLESS 节点链接已复制！\n请直接在 PassWall 节点列表通过“分享链接”导入。');},async loadStatus(){let res=await fetch('/api');let d=await res.json();this.r=d.running;if(!this.showModal){this.c=d.conf}},async saveConfig(){await fetch('/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(this.c)})},async toggleEngine(){this.c.enable=!this.c.enable;await this.saveConfig()},openNodeModal(n){if(n){this.isEdit=true;this.editNode=JSON.parse(JSON.stringify(n))}else{this.isEdit=false;this.editNode={id:'n_'+Math.random().toString(36).substr(2,9),name:'',server:'',username:'Default',password:'',sni:''}}this.showModal=true},async saveNode(){if(!this.editNode.name||!this.editNode.server){alert("别名和服务器地址不能为空");return}if(this.isEdit){let idx=this.c.nodes.findIndex(x=>x.id===this.editNode.id);if(idx>-1)this.c.nodes[idx]=this.editNode}else{this.c.nodes.push(this.editNode);if(this.c.nodes.length===1){this.c.active_node_id=this.editNode.id}}this.showModal=false;await this.saveConfig();this.loadStatus()},async delNode(id){if(!confirm("确定要删除此节点吗？"))return;this.c.nodes=this.c.nodes.filter(x=>x.id!==id);if(this.c.active_node_id===id){this.c.active_node_id=this.c.nodes.length>0?this.c.nodes[0].id:''}await this.saveConfig();this.loadStatus()}},mounted(){this.loadStatus();setInterval(this.loadStatus,2000)}}).mount('#app')</script></body></html>`