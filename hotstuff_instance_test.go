package p2p

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cypherium/cypherBFT/go-cypherium/crypto/bls"
	"github.com/cypherium/cypherBFT/go-cypherium/crypto/sha3"
	"github.com/cypherium/cypherBFT/go-cypherium/event"
	"github.com/cypherium/cypherBFT/go-cypherium/hotstuff"
	"github.com/cypherium/cypherBFT/go-cypherium/log"
	"github.com/cypherium/cypherBFT/go-cypherium/p2p/simulations/pipes"
	mathRand "math/rand"
	"net"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"
)

var (
	errReadClosed = errors.New("read closed")
)

type connection struct {
	rw    *rlpxFrameRW
	fd    net.Conn
	close chan bool
	peer  *node
}

type node struct {
	id          string
	sec         *bls.SecretKey
	pub         *bls.PublicKey
	groupPublic []*bls.PublicKey

	conn    map[string]*connection
	feed    event.Feed
	msgCh   chan Msg
	msgSub  event.Subscription // Subscription for msg event
	feedMsg bool

	members     []*node
	faultyNodes []int // for emulating faulty nodes

	hsm        *hotstuff.HotstuffProtocolManager
	leader     uint64
	stateK     uint64
	stateT     uint64
	testK      bool
	testT      bool
	fixLeader  bool
	finalState uint64

	exit chan bool

	mu sync.Mutex

	doneAt time.Time
}

func NewNode(id string) *node {
	sec := new(bls.SecretKey)
	sec.SetByCSPRNG()
	pub := sec.GetPublicKey()

	n := &node{
		id:          id,
		sec:         sec,
		pub:         pub,
		conn:        make(map[string]*connection),
		msgCh:       make(chan Msg, 5000),
		feedMsg:     false,
		faultyNodes: make([]int, 0),
		stateK:      0,
		stateT:      0,
		testT:       true,
		testK:       true,
		fixLeader:   false,
		exit:        make(chan bool),
	}

	n.msgSub = n.feed.Subscribe(n.msgCh)
	return n
}

func (n *node) SetFaultyNodes(fn []int) {
	n.faultyNodes = make([]int, 0)
	for _, f := range fn {
		n.faultyNodes = append(n.faultyNodes, f)
	}
}

func (n *node) SetFinalState(fs uint64) {
	n.finalState = fs
}

// support connect to itself
func (n *node) ConnectTo(p *node) error {
	if n.id != p.id && n.conn[p.id] != nil {
		// already connected
		return nil
	}

	var (
		aesSecret      = make([]byte, 16)
		macSecret      = make([]byte, 16)
		egressMACinit  = make([]byte, 32)
		ingressMACinit = make([]byte, 32)
	)
	for _, s := range [][]byte{aesSecret, macSecret, egressMACinit, ingressMACinit} {
		rand.Read(s)
	}
	fd0, fd1, err := pipes.TCPPipe()
	if err != nil {
		fmt.Println("fail to init tcp pipe")
		return err
	}

	//fd0.SetReadDeadline(time.Now().Add(time.Second * 200))
	//fd1.SetWriteDeadline(time.Now().Add(time.Second * 200))

	s1 := secrets{
		AES:        aesSecret,
		MAC:        macSecret,
		EgressMAC:  sha3.NewKeccak256(),
		IngressMAC: sha3.NewKeccak256(),
	}
	s1.EgressMAC.Write(egressMACinit)
	s1.IngressMAC.Write(ingressMACinit)
	n.conn[p.id] = &connection{
		rw:    newRLPXFrameRW(fd0, s1),
		fd:    fd0,
		close: make(chan bool),
		peer:  p,
	}

	s2 := secrets{
		AES:        aesSecret,
		MAC:        macSecret,
		EgressMAC:  sha3.NewKeccak256(),
		IngressMAC: sha3.NewKeccak256(),
	}
	s2.EgressMAC.Write(ingressMACinit)
	s2.IngressMAC.Write(egressMACinit)

	if n.id != p.id {
		p.conn[n.id] = &connection{
			rw:    newRLPXFrameRW(fd1, s2),
			fd:    fd1,
			close: make(chan bool),
			peer:  n,
		}
	} else {
		// connect to itself
		p.conn[n.id+"0"] = &connection{
			rw:    newRLPXFrameRW(fd1, s2),
			fd:    fd1,
			close: make(chan bool),
			peer:  n,
		}
	}

	readLoop := func(id string, conn *connection, node *node) {
		for {
			msg, err := conn.rw.ReadMsg()
			if err != nil {
				netErr, ok := err.(net.Error)
				if ok && netErr.Timeout() {
					log.Debug("Node tcp read timeout", "id", id)
				} else {
					log.Debug("Node got tcp error", "id", id, "error", err)
					break
				}
				continue
			}

			if node.feedMsg {
				node.feed.Send(msg)
			}
		}

		conn.close <- true
	}

	go readLoop(n.id, n.conn[p.id], n)
	if n.id != p.id {
		go readLoop(p.id, p.conn[n.id], p)
	} else {
		go readLoop(p.id, p.conn[n.id+"0"], p)
	}

	return nil
}

func (n *node) Read() (*Msg, error) {
	select {
	case m := <-n.msgCh:
		return &m, nil
	case <-n.msgSub.Err():
		//fmt.Println(".....closing", err)
		return nil, errReadClosed
	}
}

func (n *node) WriteTo(id string, msgCode uint64, data interface{}) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	rw := n.conn[id].rw
	return Send(rw, msgCode, data)
}

func (n *node) WriteToGroup(g []*node, msgCode uint64, data interface{}) []error {
	errs := make([]error, 0)
	for _, p := range g {
		rw := n.conn[p.id].rw
		err := Send(rw, msgCode, data)
		if err != nil {
			log.Debug("WriteToGroup failed with error", "error", err)
		}
		errs = append(errs, err)
	}

	return errs
}

func (n *node) ConnectToGroup(g []*node) {
	n.members = make([]*node, len(g))
	copy(n.members, g)

	for _, p := range n.members {
		//if p.id != n.id {
		if err := n.ConnectTo(p); err != nil {
			log.Debug("connect error", "from", p.id, "to", n.id)
		}
		//}
	}
}

func (n *node) CloseConnectionWith(p *node) {
	fd1 := n.conn[p.id].fd
	fd1.Close()

	fd2 := p.conn[n.id].fd
	fd2.Close()

	//fmt.Printf("Wait for read loop joining....")
	wait := 0

	expect := 2
	if n.id == p.id {
		expect = 1
	}

	for {
		select {
		case <-n.conn[p.id].close:
			//fmt.Printf("Got signal from %s\n\r", n.id)
			wait += 1
		case <-p.conn[n.id].close:
			//fmt.Printf("Got signal from %s\n\r", p.id)
			wait += 1
		}

		if wait == expect {
			break
		}
	}
	//fmt.Printf("done\n\r")
}

type Handler func(n *node)

func (n *node) Run(h Handler) {
	n.feedMsg = true
	if h != nil {
		go h(n)
	}
}

func (n *node) StopFeed() {
	n.feedMsg = false
	n.msgSub.Unsubscribe()
	time.Sleep(time.Millisecond * 10) // wait for the TestFeed loop quit
}

type testData struct {
	Name string
}

func feed(n *node) {
	for {
		select {
		case m := <-n.msgCh:
			log.Debug("Node got message", "node", n.id, "code", m.Code)
		case <-n.msgSub.Err():
			log.Debug("Feed exit")
			return
		}
	}
}

/////////////////////////////////////////////////////////////
// Test Hotstuff
func statesToBytes(k, t uint64) []byte {
	bufK := make([]byte, 8)
	binary.BigEndian.PutUint64(bufK, k)

	bufT := make([]byte, 8)
	binary.BigEndian.PutUint64(bufT, t)

	buf := make([]byte, 0)
	buf = append(buf, bufK...)
	buf = append(buf, bufT...)

	return buf
}

func stateToBytes(s uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, s)

	return buf
}

func bytesToUInt64(buf []byte) uint64 {
	s := binary.BigEndian.Uint64(buf)
	return s
}

func uint64ToId(i uint64) string {
	return fmt.Sprintf("%d", i)
}

func (n *node) Self() string {
	return n.id
}

func (n *node) Write(id string, m *hotstuff.HotstuffMessage) error {
	//log.Debug("--->Node send message", "from", n.id, "message", hotstuff.ReadableMsgType(m.Code), "to", id)
	return n.WriteTo(id, 0, m)
}

func (n *node) Broadcast(m *hotstuff.HotstuffMessage) []error {
	//log.Debug("--->Node broadcast message", "from", n.id, "message", hotstuff.ReadableMsgType(m.Code))
	return n.WriteToGroup(n.members, 0, m)
}

func (n *node) OnNewView(b []byte, extra [][]byte) error {
	k := bytesToUInt64(b)
	t := bytesToUInt64(b[8:])

	if k != n.stateK {
		log.Debug("state K not match ", "local", n.stateK, "remote", k)
		return fmt.Errorf("state K not match")
	}

	if t != n.stateT {
		log.Debug("state T not match", "local", n.stateT, "remote", t)
		return fmt.Errorf("state T not match")
	}

	return nil
}

func (n *node) CheckView([]byte) error {
	return nil
}

func (n *node) OnPropose(kBuf, tBuf []byte, extra []byte) error {
	if kBuf != nil && len(kBuf) > 0 {
		k := bytesToUInt64(kBuf)
		if k != (n.stateK + 1) {
			return fmt.Errorf("proposed k-state not match")
		}
	}

	if tBuf != nil && len(tBuf) > 0 {
		t := bytesToUInt64(tBuf)
		if t != (n.stateT + 1) {
			return fmt.Errorf("proposed t-state not match")
		}
	}

	elapsed := time.Now().Sub(n.doneAt).Nanoseconds() / 1000000
	log.Info("on prepare comes.", "time", elapsed)

	return nil
}

func (n *node) OnViewDone(e error, phase uint64, kSign *hotstuff.SignedState, tSign *hotstuff.SignedState) error {
	log.Debug("Node view done", "node", n.id, "k-state", n.stateK, "t-state", n.stateT, "error", e)

	if e == nil {
		if kSign != nil && !hotstuff.VerifySignature(kSign.Sign, kSign.Mask, kSign.State, n.groupPublic) {
			log.Error("view done k-state signature failed---")
			n.StopFeed()
		}

		if tSign != nil && !hotstuff.VerifySignature(tSign.Sign, tSign.Mask, tSign.State, n.groupPublic) {
			log.Error("view done t-state signature failed---")
			n.StopFeed()
		}

		if kSign != nil {
			n.stateK = bytesToUInt64(kSign.State) // update state
		}

		if tSign != nil {
			n.stateT = bytesToUInt64(tSign.State) // update state
		}
	} else {
		n.hsm.NewView()
		n.doneAt = time.Now()
	}

	if n.stateK == n.finalState || n.stateT == n.finalState {
		n.StopFeed()
	} else {
		//m := n.hsm.NewViewMessage()
		n.Write(n.id, n.hsm.NewViewMessage())
	}

	return nil
}

func (n *node) Propose() (error, []byte, []byte, []byte) {
	var ks, ts []byte
	if n.testK {
		ks = stateToBytes(n.stateK + 1)
	}

	if n.testT {
		ts = stateToBytes(n.stateT + 1)
	}

	return nil, ks, ts, nil
}

func (n *node) GetExtra() []byte {
	return nil
}

func (n *node) CurrentState() ([]byte, string) {
	var leader string
	if n.fixLeader {
		leader = uint64ToId(n.leader)
	} else {
		leader = uint64ToId(n.stateK % 4)
	}

	//log.Debug("Node current state", "node", n.id, "k-state", n.stateK, "t-state", n.stateT, "leader",leader)
	return statesToBytes(n.stateK, n.stateT), leader
}

func (n *node) GetPublicKey() []*bls.PublicKey {
	return n.groupPublic
}

func exists(n int, s []int) bool {
	for _, x := range s {
		if x == n {
			return true
		}
	}

	return false
}

func (n *node) SetLeader(l uint64) {
	n.fixLeader = true
	n.leader = l
}

func pickRandomFaultyNodes(total int, except int, max int) []int {
	faulty := make([]int, 0)

	fmt.Printf("Pick faulty node randomly: ")
	for {
		f := mathRand.Intn(total)
		if (f == except) || exists(f, faulty) {
			continue
		}

		faulty = append(faulty, f)
		if max == len(faulty) {
			return faulty
		}
	}
}

func (n *node) isFaultyNode() bool {
	for _, i := range n.faultyNodes {
		if n.id == uint64ToId(uint64(i)) {
			return true
		}
	}

	return false
}

func hotStuffHandler(n *node) {
	n.hsm.NewView()

	n.doneAt = time.Now()

	for {
		select {
		case m := <-n.msgCh:
			var payload hotstuff.HotstuffMessage
			if err := m.Decode(&payload); err != nil {
				continue
			}

			if n.isFaultyNode() {
				// i'm faulty node, ignore the message
				continue
			}

			log.Debug("<---Node  got message", "node", n.id, "message", hotstuff.ReadableMsgType(payload.Code), "to", payload.Id)
			start := time.Now()
			err := n.hsm.HandleMessage(&payload)
			if err != nil {
				log.Debug("handle message error ", "node", n.id, "error", err)
			}
			elapsed := time.Now().Sub(start).Nanoseconds() / 1000000
			log.Debug("Handle done.", "time", elapsed)

		case <-n.msgSub.Err():
			log.Debug("Feed exit")
			n.exit <- true
			return
		}
	}
}

func checkState(t *testing.T, members []*node) {
	for _, n := range members {
		if n.isFaultyNode() {
			// don't check final state
			continue
		}

		if n.stateK != n.finalState && n.stateT != n.finalState {
			t.Errorf("Error: node %s state(%d) not match with final state(%d)", n.id, n.stateK, n.finalState)
		}
	}
}

func (n *node) TestKState(test bool) {
	n.testK = test
}

func (n *node) TestTState(test bool) {
	n.testT = test
}

func joinExit(members []*node) {
	exit := 0
	exitCh := make([]chan bool, 0)
	threshold := (len(members) + 1) * 2 / 3

	for _, n := range members {
		exitCh = append(exitCh, n.exit)
	}

	// Use reflect to wait on dynamic channels
	cases := make([]reflect.SelectCase, len(members))
	for i, ch := range exitCh {
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ch)}
	}

	for {
		chosen, _, _ := reflect.Select(cases)
		log.Debug("node exit", "node", chosen)
		exit += 1
		if exit >= threshold {
			break
		}

	}
}

func makeMembers(total int) ([]*node, []*bls.PublicKey) {
	pubVec := make([]*bls.PublicKey, 0)

	// n0 is leader, others are member
	members := make([]*node, 0)
	for i := 0; i < total; i++ {
		n := NewNode(uint64ToId(uint64(i)))
		members = append(members, n)
		pubVec = append(pubVec, n.pub)
	}

	for _, m := range members {
		m.groupPublic = pubVec
		m.ConnectToGroup(members)
	}

	return members, pubVec
}

func testHotstuff_4_Nodes_TState(t *testing.T) {
	//faultyNodes := pickRandomFaultyNodes(MEMBERSIZE, leaderIndex, 1) // nodes that don't respond

	members, _ := makeMembers(4)

	for _, n := range members {
		n.SetFinalState(100)
		n.TestKState(false)
		n.TestTState(true)
		n.hsm = hotstuff.NewHotstuffProtocolManager(n, n.sec, n.pub, time.Second*21)
		n.Run(hotStuffHandler)
	}

	joinExit(members)
	checkState(t, members)
}

func testHotstuff_4_Nodes_KState(t *testing.T) {
	//faultyNodes := pickRandomFaultyNodes(MEMBERSIZE, leaderIndex, 1) // nodes that don't respond

	members, _ := makeMembers(5)

	for _, n := range members {

		n.SetFinalState(1)
		n.TestKState(true)
		n.TestTState(true)
		n.hsm = hotstuff.NewHotstuffProtocolManager(n, n.sec, n.pub, time.Second*21)
		n.Run(hotStuffHandler)
	}

	joinExit(members)
	checkState(t, members)
}

func testHotstuff_4_Nodes_KState_1_f(t *testing.T) {

	initLogger(5)
	log.Info("test start")

	total := 4
	//leader := 2
	//faultyNodes := pickRandomFaultyNodes(total, leader, 1) // nodes that don't respond

	members, _ := makeMembers(total)

	for _, n := range members {
		//n.SetFaultyNodes(faultyNodes)
		//n.SetLeader(uint64(leader))
		n.SetFinalState(1000)
		n.TestKState(true)
		n.TestTState(true)

		n.hsm = hotstuff.NewHotstuffProtocolManager(n, n.sec, n.pub, time.Second*60)
		n.Run(hotStuffHandler)
	}

	for _, n := range members {
		n.hsm.Stop()
	}
	joinExit(members)

	checkState(t, members)

}

func testHotstuff_4_Nodes_KTState(t *testing.T) {
	//faultyNodes := pickRandomFaultyNodes(MEMBERSIZE, leaderIndex, 1) // nodes that don't respond

	members, _ := makeMembers(4)

	for _, n := range members {
		n.SetFinalState(100)
		n.TestKState(true)
		n.TestTState(true)
		n.hsm = hotstuff.NewHotstuffProtocolManager(n, n.sec, n.pub, time.Second*21)
		n.Run(hotStuffHandler)
	}

	joinExit(members)
	checkState(t, members)
}

func testHotstuff_7_Nodes_KState(t *testing.T) {
	members, _ := makeMembers(7)

	for _, n := range members {
		n.SetFinalState(100)
		n.TestKState(true)
		n.TestTState(false)

		n.hsm = hotstuff.NewHotstuffProtocolManager(n, n.sec, n.pub, time.Second*21)
		n.Run(hotStuffHandler)
	}

	joinExit(members)
	checkState(t, members)
}

func testHotstuff_7_Nodes_TState(t *testing.T) {
	members, _ := makeMembers(7)

	for _, n := range members {
		n.SetFinalState(100)
		n.TestKState(false)
		n.TestTState(true)

		n.hsm = hotstuff.NewHotstuffProtocolManager(n, n.sec, n.pub, time.Second*21)
		n.Run(hotStuffHandler)
	}

	joinExit(members)
	checkState(t, members)
}

func testHotstuff_7_Nodes_KTState(t *testing.T) {
	members, _ := makeMembers(7)

	for _, n := range members {
		n.SetFinalState(100)
		n.TestKState(true)
		n.TestTState(true)

		n.hsm = hotstuff.NewHotstuffProtocolManager(n, n.sec, n.pub, time.Second*21)
		n.Run(hotStuffHandler)
	}

	joinExit(members)
	checkState(t, members)
}

func initLogger(level int) {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(level))
	log.Root().SetHandler(glogger)
}
