// go test -tags bn256

package hotstuff

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/cypherium/cypherBFT/go-cypherium/common"
	"github.com/cypherium/cypherBFT/go-cypherium/crypto"
	"github.com/cypherium/cypherBFT/go-cypherium/crypto/bls"
	"github.com/cypherium/cypherBFT/go-cypherium/event"
	"testing"
	"time"
)

type app struct {
	block  int
	pubVec []*bls.PublicKey
	feed   event.Feed
	msgCh  chan *HotstuffMessage
	msgSub event.Subscription // Subscription for msg event
	hsm    *HotstuffProtocolManager
}

func (a *app) Self() string {
	return "app"
}

func (a *app) Write(id string, m *HotstuffMessage) error {
	if id == a.Self() {
		a.feed.Send(m)
	}

	return nil
}

func (a *app) Broadcast(m *HotstuffMessage) []error {
	return nil
}

func (a *app) CheckView([]byte) error {
	return nil
}

func (a *app) OnNewView(st []byte, extra [][]byte) error {
	return nil
}

func (a *app) OnPropose([]byte, []byte, []byte) error {
	return nil
}

func (a *app) OnViewDone(e error, phase uint64, kSign *SignedState, tSign *SignedState) error {
	fmt.Println("one view done", e)
	if e == ErrViewTimeout {
		a.block += 1
	}
	return nil
}

func (a *app) Propose() (e error, kState []byte, tState []byte, extra []byte) {
	return nil, []byte("123"), []byte("abc"), []byte("extra")
}

//func (a *app) NextLeader() string {
//	return "abc"
//}

func (a *app) CurrentState() ([]byte, string) {
	return []byte("state"), "abc"
}

func (a *app) GetExtra() []byte {
	return nil
}

func (a *app) GetPublicKey() []*bls.PublicKey {
	return a.pubVec
}

func createKeyPairs(n int) ([]*bls.PublicKey, []*bls.SecretKey) {
	pubVec := make([]*bls.PublicKey, 0)
	secVec := make([]*bls.SecretKey, 0)

	for i := 0; i < n; i++ {
		sec := new(bls.SecretKey)
		sec.SetByCSPRNG()
		pub := sec.GetPublicKey()
		pubVec = append(pubVec, pub)
		secVec = append(secVec, sec)
	}
	return pubVec, secVec
}

func (a *app) initApp(pubVec []*bls.PublicKey, hsm *HotstuffProtocolManager) {
	a.pubVec = make([]*bls.PublicKey, 0)
	for _, p := range pubVec {
		a.pubVec = append(a.pubVec, p)
	}

	a.hsm = hsm
}

func (a *app) run() {
	for {
		select {
		case m := <-a.msgCh:
			fmt.Println("handle message", "code", ReadableMsgType(m.Code))
			a.hsm.HandleMessage(m)
		case <-a.msgSub.Err():
			fmt.Printf("app exit\n\r")
			return
		}
	}

}

func (a *app) stop() {
	a.msgSub.Unsubscribe()
	time.Sleep(time.Millisecond * 10)
}

func newApp() *app {
	a := &app{
		block: 0,
		msgCh: make(chan *HotstuffMessage, 50),
	}

	a.msgSub = a.feed.Subscribe(a.msgCh)
	return a
}

func initProtocol(a HotStuffApplication, pubVec []*bls.PublicKey, secVec []*bls.SecretKey) *HotstuffProtocolManager {
	return NewHotstuffProtocolManager(a, secVec[0], pubVec[0], time.Second)
}

func addQuorum(t *testing.T, v *View, pub *bls.PublicKey, sec *bls.SecretKey, index int) *Quorum {
	sig := sec.SignHash(crypto.Keccak256(v.currentState))

	if !sig.VerifyHash(pub, crypto.Keccak256(v.currentState)) {
		t.Errorf("add Quorum failed: %d", index)
	}

	var qrum Quorum
	if err := qrum.PubKey.Deserialize(pub.Serialize()); err != nil {
		t.Errorf("add Quorum failed @pubkey: %d", index)
	}

	if err := qrum.KSign.Deserialize(sig.Serialize()); err != nil {
		t.Errorf("add Quorum failed @signature: %d", index)
	}

	qrum.ValidKSign = true

	qrum.Index = index

	return &qrum
}

func TestInit(t *testing.T) {
	err := bls.Init(bls.CurveFp254BNb)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBasic(t *testing.T) {
	t.Log("testBasic")
	var sec1 bls.SecretKey
	var sec2 bls.SecretKey
	sec1.SetByCSPRNG()
	sec2.SetByCSPRNG()

	pub1 := sec1.GetPublicKey()
	pub2 := sec2.GetPublicKey()

	m := "test test"
	sign1 := sec1.Sign(m)
	sign2 := sec2.Sign(m)

	t.Log("sign1    :", sign1.GetHexString())
	sign1.Add(sign2)
	t.Log("sign1 add:", sign1.GetHexString())
	pub1.Add(pub2)
	if !sign1.Verify(pub1, m) {
		t.Fail()
	}
}

func testQC(t *testing.T, total int) {
	a := &app{block: 0}
	pubVec, secVec := createKeyPairs(total)
	hsm := initProtocol(a, pubVec, secVec)
	a.initApp(pubVec, hsm)
	v, _ := hsm.newView()

	for i := 0; i < total; i++ {
		q := addQuorum(t, v, pubVec[i], secVec[i], i)
		v.highQuorum = append(v.highQuorum, q)
	}

	// verify each quorum
	for i := 0; i < total; i++ {
		if !v.highQuorum[i].KSign.VerifyHash(&v.highQuorum[i].PubKey, crypto.Keccak256(v.currentState)) {
			t.Errorf("Quorum test failed: %d", i)
		}
	}

	hsm.aggregateQC(v, "high", v.highQuorum)

	t.Logf("mask: %s", hex.EncodeToString(v.qc["high"].mask))
	t.Logf("sig: %s", hex.EncodeToString(v.qc["high"].kSign.Serialize()))

	// verify aggregated signature
	if !VerifySignature(v.qc["high"].kSign.Serialize(), v.qc["high"].mask, v.currentState, v.groupPublicKey) {
		t.Errorf("aggregated quorum test failed")
	}
}

func TestQC(t *testing.T) {
	testQC(t, 4)
	testQC(t, 7)
	testQC(t, 10)
	testQC(t, 50)
	testQC(t, 100)
}

////////////////////////////////////////////////////////////////
func TestCreateView(t *testing.T) {
	a := &app{block: 0}
	pubVec, secVec := createKeyPairs(4)
	hsm := initProtocol(a, pubVec, secVec)
	a.initApp(pubVec, hsm)

	v1, _ := hsm.newView()
	v2 := hsm.createView(false, PhasePrepare, v1.leaderId, v1.currentState)

	if v1.hash != v2.hash {
		t.Errorf("CreateView failed")
	}
}

////////////////////////////////////////////////////////////////
func TestViewTimeout(t *testing.T) {
	a := newApp()
	pubVec, secVec := createKeyPairs(4)
	hsm := initProtocol(a, pubVec, secVec)
	a.initApp(pubVec, hsm)

	hsm.setTimeoutTicker(time.Second)

	go a.run()

	v, _ := hsm.newView()
	hsm.addView(v)

	// replica timer
	time.Sleep(time.Second * 2)
	if a.block != 1 {
		t.Errorf("view timer not triggered")
	}

	hsm.addView(v)

	// leader timer
	time.Sleep(time.Second * 2)
	if a.block != 2 {
		t.Errorf("view timer not triggered")
	}

	a.stop()
}

////////////////////////////////////////////////////////////////
func TestMessageToQuorum_Only_KSign(t *testing.T) {
	a := &app{block: 0}
	pubVec, secVec := createKeyPairs(4)
	hsm := initProtocol(a, pubVec, secVec)
	a.initApp(pubVec, hsm)

	v, _ := hsm.newView()

	sig := hsm.secretKey.SignHash(crypto.Keccak256(v.currentState)).Serialize()
	msg := hsm.newMsg(MsgNewView, v.hash, nil, sig, nil)

	err, qrum := v.msgToQuorum(msg)
	if err != nil {
		t.Errorf("msgToQuorum failed %v", err)
	}

	if qrum.Index != 0 {
		t.Errorf("msgToQuorum index mismatch %d, should be %d", qrum.Index, 0)
	}

	if !qrum.ValidKSign {
		t.Errorf("msgToQuorum ValidKSign should be true")
	}

	if qrum.ValidTSign {
		t.Errorf("msgToQuorum ValidTSign should be false")
	}

	if !qrum.KSign.VerifyHash(&qrum.PubKey, crypto.Keccak256(v.currentState)) {
		t.Errorf("quorum k-signature verification failed")
	}
}

func TestMessageToQuorum_Only_TSign(t *testing.T) {
	a := &app{block: 0}
	pubVec, secVec := createKeyPairs(4)
	hsm := initProtocol(a, pubVec, secVec)
	a.initApp(pubVec, hsm)

	v, _ := hsm.newView()

	sig := hsm.secretKey.SignHash(crypto.Keccak256(v.currentState)).Serialize()
	msg := hsm.newMsg(MsgNewView, v.hash, nil, nil, sig)

	err, qrum := v.msgToQuorum(msg)
	if err != nil {
		t.Errorf("msgToQuorum failed %v", err)
	}

	if qrum.Index != 0 {
		t.Errorf("msgToQuorum index mismatch %d, should be %d", qrum.Index, 0)
	}

	if qrum.ValidKSign {
		t.Errorf("msgToQuorum ValidKSign should be false")
	}

	if !qrum.ValidTSign {
		t.Errorf("msgToQuorum ValidTSign should be true")
	}

	if !qrum.TSign.VerifyHash(&qrum.PubKey, crypto.Keccak256(v.currentState)) {
		t.Errorf("quorum t-signature verification failed")
	}
}

func TestMessageToQuorum_Both(t *testing.T) {
	a := &app{block: 0}
	pubVec, secVec := createKeyPairs(4)
	hsm := initProtocol(a, pubVec, secVec)
	a.initApp(pubVec, hsm)

	v, _ := hsm.newView()

	sig := hsm.secretKey.SignHash(crypto.Keccak256(v.currentState)).Serialize()
	msg := hsm.newMsg(MsgNewView, v.hash, nil, sig, sig)

	err, qrum := v.msgToQuorum(msg)
	if err != nil {
		t.Errorf("msgToQuorum failed %v", err)
	}

	if qrum.Index != 0 {
		t.Errorf("msgToQuorum index mismatch %d, should be %d", qrum.Index, 0)
	}

	if !qrum.ValidKSign {
		t.Errorf("msgToQuorum ValidKSign should be true")
	}

	if !qrum.ValidTSign {
		t.Errorf("msgToQuorum ValidTSign should be true")
	}

	if !qrum.KSign.VerifyHash(&qrum.PubKey, crypto.Keccak256(v.currentState)) {
		t.Errorf("quorum k-signature verification failed")
	}

	if !qrum.TSign.VerifyHash(&qrum.PubKey, crypto.Keccak256(v.currentState)) {
		t.Errorf("quorum t-signature verification failed")
	}

}

////////////////////////////////////////////////////////////////
type Seed struct {
	data []byte
}

func NewSeed(s [32]byte) *Seed {
	seed := &Seed{
		data: make([]byte, 32),
	}

	copy(seed.data, s[:])
	return seed
}
func (s *Seed) Read(buf []byte) (int, error) {
	n := len(buf)
	for i := 0; i < n; i++ {
		buf[i] = s.data[i]
	}
	return n, nil
}

func TestSecretKey(t *testing.T) {
	hash := sha256.Sum256([]byte("hello"))
	//fmt.Printf("(Hash) =%x\n", hash[:])

	s1 := NewSeed(hash)
	bls.SetRandFunc(s1)
	var sec bls.SecretKey
	sec.SetByCSPRNG()
	buf := sec.GetLittleEndian()
	//fmt.Printf("(SeqRead) buf=%x\n", buf)
	for i := 0; i < len(buf)-1; i++ {
		if buf[i] != hash[i] {
			t.Fatal("buf")
		}
	}

	pub := sec.GetPublicKey()
	sign := sec.SignHash(hash[:])
	if !sign.VerifyHash(pub, hash[:]) {
		t.Fatal("sign failed")
	}

	bls.SetRandFunc(rand.Reader)
	sec.SetByCSPRNG()
	buf = sec.GetLittleEndian()
	//fmt.Printf("(rand.Reader) buf=%x\n", buf)
	bls.SetRandFunc(nil)
	sec.SetByCSPRNG()
	buf = sec.GetLittleEndian()
	//fmt.Printf("(default) buf=%x\n", buf)

}

////////////////////////////////////////////////////////////////
func TestEDDSAToBLS(t *testing.T) {
	hash := sha256.Sum256([]byte("hello"))

	bPub, bSec, _ := crypto.EDDSAToBLS(hash[:])
	var sec bls.SecretKey

	if err := sec.Deserialize(bSec); err != nil {
		t.Fatal("fail to deserialize secret key")
	}

	var pub bls.PublicKey
	if err := pub.Deserialize(bPub); err != nil {
		t.Fatal("fail to deserialize public key")
	}

	sign := sec.SignHash(hash[:])
	if !sign.VerifyHash(&pub, hash[:]) {
		t.Fatal("faile to verify signature")
	}
}

func makeMask(mask []int, total int) []byte {
	size := total >> 3
	if total&0x7 > 0 {
		size += 1
	}
	result := make([]byte, size)
	for i := range result {
		result[i] = 0
	}

	for _, b := range mask {
		result[b>>3] |= (byte)(1) << uint(b%8)
	}

	return result
}

func TestMaskToException(t *testing.T) {
	pubVec, _ := createKeyPairs(100)

	maskInt := []int{0, 1, 2, 7, 25, 45, 87, 99}
	mask := makeMask(maskInt, 100)

	exception := MaskToException(mask, pubVec)

	fmt.Printf("len = %d, mask = 0x%x\n", len(exception), mask)

	if len(exception) != len(maskInt) {
		t.Fatal("wrong exception length", len(exception))
	}

	for i, index := range maskInt {
		if !exception[i].IsEqual(pubVec[index]) {
			t.Fatal("error exception")
		}
	}

	maskInt2 := []int{}
	mask2 := makeMask(maskInt2, 100)

	exception2 := MaskToException(mask2, pubVec)
	if len(exception2) != 0 {
		t.Fatal("wrong exception length")
	}
}

func TestUnhandledMsg(t *testing.T) {
	a := newApp()
	pubVec, secVec := createKeyPairs(4)
	hsm := initProtocol(a, pubVec, secVec)
	a.initApp(pubVec, hsm)

	hsm.setTimeoutTicker(time.Second)

	go a.run()

	m := hsm.newMsg(MsgStartNewView, common.Hash{}, nil, nil, nil)
	m.touch()

	hsm.addToUnhandled(m)

	if len(hsm.unhandledMsg) != 1 {
		t.Fatal("unhandled message list should have one item")
	}

	time.Sleep(time.Second * 2)

	if len(hsm.unhandledMsg) != 0 {
		t.Fatal("unhandled message list is not cleared")
	}

	hsm.addToUnhandled(m)
	if len(hsm.unhandledMsg) != 1 {
		t.Fatal("unhandled message list should have one item")
	}

	for k := range hsm.unhandledMsg {
		hsm.removeFromUnhandled(k)
	}

	if len(hsm.unhandledMsg) != 0 {
		t.Fatal("unhandled message list is not cleared")
	}
}

func TestMain(m *testing.M) {
	m.Run()
}
