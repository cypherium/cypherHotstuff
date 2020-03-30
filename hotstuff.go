package hotstuff

import (
	"encoding/hex"
	"fmt"
	"time"

	"bytes"

	"github.com/cypherium/cypherBFT/go-cypherium/common"
	"github.com/cypherium/cypherBFT/go-cypherium/crypto"
	"github.com/cypherium/cypherBFT/go-cypherium/crypto/bls"
	"github.com/cypherium/cypherBFT/go-cypherium/log"
	"github.com/cypherium/cypherBFT/go-cypherium/rlp"
)

var (
	ErrNewViewFail          = fmt.Errorf("hotstuff new view fail")
	ErrUnhandledMsg         = fmt.Errorf("hotstuff unhandled message")
	ErrViewTimeout          = fmt.Errorf("hotstuff view timeout")
	ErrQCVerification       = fmt.Errorf("hotstuff QC not valid")
	ErrInvalidReplica       = fmt.Errorf("hotstuff replica not valid")
	ErrInvalidQuorumMessage = fmt.Errorf("hotstuff quorum message not valid")
	ErrInsufficientQC       = fmt.Errorf("hotstuff QC insufficient")
	ErrInvalidHighQC        = fmt.Errorf("hotstuff highQC invalid")
	ErrInvalidPrepareQC     = fmt.Errorf("hotstuff prepareQC invalid")
	ErrInvalidPreCommitQC   = fmt.Errorf("hotstuff preCommitQC invalid")
	ErrInvalidCommitQC      = fmt.Errorf("hotstuff commitQC invalid")
	ErrInvalidProposal      = fmt.Errorf("hotstuff proposal invalid")
	ErrInvalidPublicKey     = fmt.Errorf("invalid public key for bls deserialize")
	ErrViewPhaseNotMatch    = fmt.Errorf("hotstuff view phase not match")
	ErrViewOldPhase         = fmt.Errorf("hotstuff old phase ")

	ErrMissingView       = fmt.Errorf("hotstuff view missing")
	ErrInvalidLeaderView = fmt.Errorf("hotstuff invalid leader view")
	ErrExistingView      = fmt.Errorf("hotstuff view existing")
	ErrViewIdNotMatch    = fmt.Errorf("hotstuff view id not match")

	ErrOldState    = fmt.Errorf("hotstuff view state too old")
	ErrFutureState = fmt.Errorf("hotstuff view state of future")
)

const (
	MsgNewView = iota
	MsgPrepare
	MsgVotePrepare
	MsgPreCommit
	MsgVotePreCommit
	MsgCommit
	MsgVoteCommit
	MsgDecide

	// pseudo messages
	MsgCollectTimeoutView // for handling timeout
	MsgStartNewView       // for handling new view from app
	MsgTryPropose
)

func ReadableMsgType(m uint64) string {
	switch {
	case m == MsgNewView:
		return "MsgNewView"
	case m == MsgPrepare:
		return "MsgPrepare"
	case m == MsgVotePrepare:
		return "MsgVotePrepare"
	case m == MsgPreCommit:
		return "MsgPreCommit"
	case m == MsgVotePreCommit:
		return "MsgVotePreCommit"
	case m == MsgCommit:
		return "MsgCommit"
	case m == MsgVoteCommit:
		return "MsgVoteCommit"
	case m == MsgDecide:
		return "MsgDecide"
	case m == MsgCollectTimeoutView:
		return "MsgCollectTimeoutView"
	case m == MsgStartNewView:
		return "MsgStartNewView"
	case m == MsgTryPropose:
		return "MsgTryPropose"

	default:
		return "unknown"
	}
}

const (
	PhasePrepare    = iota
	PhaseTryPropose // pseudo phase, used to describe the phase between onNewView and Propose successfully
	PhasePreCommit
	PhaseCommit
	PhaseDecide
	PhaseFinal
)

func readablePhase(code uint64) string {
	switch {
	case code == PhasePrepare:
		return "PhasePrepare"
	case code == PhaseTryPropose:
		return "PhasePropose"
	case code == PhasePreCommit:
		return "PhasePreCommit"
	case code == PhaseCommit:
		return "PhaseCommit"
	case code == PhaseDecide:
		return "PhaseDecide"
	case code == PhaseFinal:
		return "PhaseFinal"
	default:
		return "unknown"
	}
}

// Proposed K or T state with signature and mask, only for OnViewDone() interface
type SignedState struct {
	State []byte
	Sign  []byte
	Mask  []byte
}

type HotStuffApplication interface {
	Self() string
	Write(string, *HotstuffMessage) error
	Broadcast(*HotstuffMessage) []error

	GetPublicKey() []*bls.PublicKey

	OnNewView(currentState []byte, extra [][]byte) error
	OnPropose(kState []byte, tState []byte, extra []byte) error
	OnViewDone(e error, phase uint64, kSign *SignedState, tSign *SignedState) error

	CheckView(currentState []byte) error
	Propose() (e error, kState []byte, tState []byte, extra []byte)
	CurrentState() ([]byte, string)
	GetExtra() []byte // only for new-view procedure
}

type Quorum struct {
	Index      int // index in the group public keys
	PubKey     *bls.PublicKey
	KSign      bls.Sign
	TSign      bls.Sign
	ValidKSign bool
	ValidTSign bool
}

type QC struct {
	kSign *bls.Sign
	tSign *bls.Sign
	mask  []byte
}

type HotstuffMessage struct {
	Code   uint64
	ViewId common.Hash
	Id     string
	PubKey []byte

	// The usage of these "DataX" if different per message
	DataA []byte
	DataB []byte
	DataC []byte

	DataD []byte
	DataE []byte
	DataF []byte

	ReceivedAt time.Time
}

func (m *HotstuffMessage) touch() {
	m.ReceivedAt = time.Now()
}

type View struct {
	hash           common.Hash // hash on "currentState + leaderId", hence should be unique and equal for the same view and leader
	createdAt      time.Time
	leaderId       string
	phaseAsLeader  uint64
	phaseAsReplica uint64
	currentState   []byte
	proposedKState []byte
	proposedTState []byte

	highQuorum      []*Quorum
	prepareQuorum   []*Quorum
	preCommitQuorum []*Quorum
	commitQuorum    []*Quorum
	qc              map[string]*QC
	leaderMsg       map[uint64]*HotstuffMessage // record messages from leader to replica: MsgPrepare, MsgPreCommit, MsgCommit, MsgDecide

	tReplica       *time.Timer
	tLeader        *time.Timer
	stopTReplicaCh chan bool // stop the tReplica go routine
	stopTLeaderCh  chan bool // stop the tLeader go routine

	groupPublicKey []*bls.PublicKey
	threshold      int

	extra [][]byte

	futureNewViewMsg []*HotstuffMessage
}

func (v *View) hasKState() bool {
	return v.proposedKState != nil && len(v.proposedKState) > 0
}

func (v *View) hasTState() bool {
	return v.proposedTState != nil && len(v.proposedTState) > 0
}

type HotstuffProtocolManager struct {
	secretKey    *bls.SecretKey
	publicKey    *bls.PublicKey
	timeout      time.Duration
	tickerPeriod time.Duration
	views        map[common.Hash]*View
	leaderView   *View
	app          HotStuffApplication
	exit         chan bool
	unhandledMsg map[common.Hash]*HotstuffMessage // messages which is not handled(which phase is ahead of local's)
}

func NewHotstuffProtocolManager(a HotStuffApplication, secretKey *bls.SecretKey, publicKey *bls.PublicKey, t time.Duration) *HotstuffProtocolManager {
	manager := &HotstuffProtocolManager{
		secretKey:    secretKey,
		publicKey:    publicKey,
		app:          a,
		timeout:      t,
		tickerPeriod: 60 * time.Second,
		views:        make(map[common.Hash]*View),
		exit:         make(chan bool),
		unhandledMsg: make(map[common.Hash]*HotstuffMessage),
	}

	if int64(t) > 0 {
		manager.timeout = t
	}

	go manager.collectTimeoutView()

	return manager
}

func CalcThreshold(size int) int {
	return (size + 1) * 2 / 3
}

func (hsm *HotstuffProtocolManager) UpdateKeyPair(sec *bls.SecretKey) {
	hsm.secretKey = sec
	hsm.publicKey = sec.GetPublicKey()
}

func (v *View) lookupReplica(pubKey *bls.PublicKey) int {
	for i, p := range v.groupPublicKey {
		if p.IsEqual(pubKey) {
			return i
		}
	}
	/*??
	log.Debug("lookupReplica miss replica's public key", "key", hex.EncodeToString(pubKey.Serialize()))

	log.Debug("lookupReplica start dumping committee members' public key ====================")
	for i, p := range v.groupPublicKey {
		log.Debug("Public Key", "index", i, "key", hex.EncodeToString(p.Serialize()))
	}
	log.Debug("lookupReplica finish dumping committee members' public key ====================")
	*/
	return -1
}

func (v *View) msgToQuorum(m *HotstuffMessage) (error, *Quorum) {
	var qrum Quorum
	qrum.PubKey = bls.GetPublicKey(m.PubKey)
	if qrum.PubKey == nil {
		return ErrInvalidPublicKey, nil
	}
	/*
		if err := qrum.PubKey.Deserialize(m.PubKey); err != nil {
			return err, nil
		}
	*/
	if m.DataB != nil && len(m.DataB) > 0 {
		if err := qrum.KSign.Deserialize(m.DataB); err != nil {
			qrum.ValidKSign = false
		} else {
			qrum.ValidKSign = true
		}
	}

	if m.DataC != nil && len(m.DataC) > 0 {
		if err := qrum.TSign.Deserialize(m.DataC); err != nil {
			qrum.ValidTSign = false
		} else {
			qrum.ValidTSign = true
		}
	}

	if !qrum.ValidKSign && !qrum.ValidTSign {
		return ErrInvalidQuorumMessage, nil
	}

	index := v.lookupReplica(qrum.PubKey)
	if -1 == index {
		return ErrInvalidReplica, nil
	}
	qrum.Index = index

	return nil, &qrum
}

func (hsm *HotstuffProtocolManager) newMsg(code uint64, viewId common.Hash, a []byte, b []byte, c []byte) *HotstuffMessage {
	msg := &HotstuffMessage{
		Code:   code,
		ViewId: viewId,
		Id:     hsm.app.Self(),
	}

	if hsm.publicKey != nil {
		bPubKey := hsm.publicKey.Serialize()
		msg.PubKey = make([]byte, len(bPubKey))
		copy(msg.PubKey, bPubKey)
	}

	if a != nil && len(a) > 0 {
		msg.DataA = make([]byte, len(a))
		copy(msg.DataA, a)
	}

	if b != nil && len(b) > 0 {
		msg.DataB = make([]byte, len(b))
		copy(msg.DataB, b)
	}

	if c != nil && len(c) > 0 {
		msg.DataC = make([]byte, len(c))
		copy(msg.DataC, c)
	}

	return msg
}

func (hsm *HotstuffProtocolManager) newView() (*View, []byte) {
	currentState, leaderId := hsm.app.CurrentState()
	if leaderId == "" {
		return nil, nil
	}

	v := &View{
		phaseAsReplica:   PhasePrepare,
		leaderId:         leaderId,
		highQuorum:       make([]*Quorum, 0),
		prepareQuorum:    make([]*Quorum, 0),
		preCommitQuorum:  make([]*Quorum, 0),
		commitQuorum:     make([]*Quorum, 0),
		qc:               make(map[string]*QC),
		leaderMsg:        make(map[uint64]*HotstuffMessage),
		stopTLeaderCh:    make(chan bool),
		stopTReplicaCh:   make(chan bool),
		extra:            make([][]byte, 0),
		futureNewViewMsg: make([]*HotstuffMessage, 0),
	}

	v.currentState = make([]byte, len(currentState))
	copy(v.currentState, currentState)

	v.hash = crypto.Keccak256Hash([]byte(v.leaderId), v.currentState)

	groupPublicKey := hsm.app.GetPublicKey()
	v.groupPublicKey = make([]*bls.PublicKey, 0)
	for _, p := range groupPublicKey {
		v.groupPublicKey = append(v.groupPublicKey, p)
	}

	v.threshold = CalcThreshold(len(groupPublicKey))

	return v, hsm.app.GetExtra()
}

func (hsm *HotstuffProtocolManager) createView(asLeader bool, phase uint64, leaderId string, currentState []byte) *View {
	v := &View{
		leaderId:         leaderId,
		highQuorum:       make([]*Quorum, 0),
		prepareQuorum:    make([]*Quorum, 0),
		preCommitQuorum:  make([]*Quorum, 0),
		commitQuorum:     make([]*Quorum, 0),
		qc:               make(map[string]*QC),
		leaderMsg:        make(map[uint64]*HotstuffMessage),
		extra:            make([][]byte, 0),
		futureNewViewMsg: make([]*HotstuffMessage, 0),
	}

	if asLeader {
		v.phaseAsLeader = phase
	} else {
		v.phaseAsReplica = phase
	}

	v.currentState = make([]byte, len(currentState))
	copy(v.currentState, currentState)

	v.hash = crypto.Keccak256Hash([]byte(v.leaderId), v.currentState)

	groupPublicKey := hsm.app.GetPublicKey()
	v.groupPublicKey = make([]*bls.PublicKey, 0)
	for _, p := range groupPublicKey {
		v.groupPublicKey = append(v.groupPublicKey, p)
	}

	v.threshold = CalcThreshold(len(groupPublicKey))

	return v
}

func (hsm *HotstuffProtocolManager) updateViewPublicKey(v *View) {
	groupPublicKey := hsm.app.GetPublicKey()
	v.groupPublicKey = make([]*bls.PublicKey, 0)
	for _, p := range groupPublicKey {
		v.groupPublicKey = append(v.groupPublicKey, p)
	}
}

func (hsm *HotstuffProtocolManager) DumpView(v *View, asLeader bool) {
	/*
		log.Debug("Dump View ================", "viewID", v.hash)

		if asLeader {
			log.Debug("View phase", "asLeader", readablePhase(v.phaseAsLeader))
		} else {
			log.Debug("View phase", "asReplica", readablePhase(v.phaseAsLeader))
		}

		for i, p := range v.groupPublicKey {
			if i == 0 || i == 1 || i == (len(v.groupPublicKey)-1) {
				log.Debug("Public Key", "index", i, "key", hex.EncodeToString(p.Serialize()))
			}
		}

		log.Debug("Dump View End ================>>")
	*/
}

func (hsm *HotstuffProtocolManager) addView(v *View) {
	v.createdAt = time.Now()
	hsm.views[v.hash] = v
}

func (hsm *HotstuffProtocolManager) removeView(v *View) {
	delete(hsm.views, v.hash)
}

func (hsm *HotstuffProtocolManager) lookupView(hash common.Hash) (*View, bool) {
	v, e := hsm.views[hash]
	return v, e
}

func (hsm *HotstuffProtocolManager) lockView(v *View) {
	for k, view := range hsm.views {
		if bytes.Equal(v.hash[:], view.hash[:]) {
			continue
		}

		// reserve views with future new view message
		if len(view.futureNewViewMsg) > 0 {
			continue
		}

		log.Debug("lockView remove view", "viewId", k)
		delete(hsm.views, k)
	}
}

func (hsm *HotstuffProtocolManager) viewDone(v *View, kSign []byte, tSign []byte, mask []byte, e error) {
	phase := v.phaseAsReplica
	if e != nil {
		log.Warn("view finished with error", "error", e, "ViewId", v.hash)
		hsm.app.OnViewDone(e, phase, nil, nil)
	} else {
		elapsed := time.Now().Sub(v.createdAt).Nanoseconds() / 1000000

		log.Debug("view finished successfully", "ViewId", v.hash, "timeElapsed", elapsed)

		var kSignedState, tSignedState *SignedState
		if v.hasKState() {
			kSignedState = &SignedState{
				State: v.proposedKState,
				Sign:  kSign,
				Mask:  mask,
			}
			/*
				kSignedState = &SignedState{
					State: make([]byte, len(v.proposedKState)),
					Sign:  make([]byte, len(kSign)),
					Mask:  make([]byte, len(mask)),
				}

				copy(kSignedState.State, v.proposedKState)
				copy(kSignedState.Sign, kSign)
				copy(kSignedState.Mask, mask)
			*/
		}

		if v.hasTState() {
			tSignedState = &SignedState{
				State: v.proposedTState,
				Sign:  tSign,
				Mask:  mask,
			}
			/*
				tSignedState = &SignedState{
					State: make([]byte, len(v.proposedTState)),
					Sign:  make([]byte, len(tSign)),
					Mask:  make([]byte, len(mask)),
				}

				copy(tSignedState.State, v.proposedTState)
				copy(tSignedState.Sign, tSign)
				copy(tSignedState.Mask, mask)
			*/
		}

		hsm.app.OnViewDone(nil, phase, kSignedState, tSignedState)
	}
}

// for replica
func (hsm *HotstuffProtocolManager) NewView() error {
	v, extra := hsm.newView()
	if v == nil {
		return ErrNewViewFail
	}

	if _, exist := hsm.lookupView(v.hash); !exist {
		hsm.addView(v)
	}

	sig := hsm.secretKey.SignHash(crypto.Keccak256(v.currentState)).Serialize()
	msg := hsm.newMsg(MsgNewView, v.hash, v.currentState, sig, extra)

	log.Debug("New View", "leader", v.leaderId, "ViewID", common.HexString(v.hash[:]))
	err := hsm.app.Write(v.leaderId, msg)

	return err
}

func (hsm *HotstuffProtocolManager) aggregateQC(v *View, phase string, qrum []*Quorum) error {
	var kSign bls.Sign
	var tSign bls.Sign

	hasKSign := false
	hasTSign := false

	size := len(v.groupPublicKey) >> 3
	if len(v.groupPublicKey)&0x7 > 0 {
		size += 1
	}

	mask := make([]byte, size)
	for i, q := range qrum {
		if i == 0 {
			if q.ValidKSign {
				if err := kSign.Deserialize(q.KSign.Serialize()); err != nil {
					return err
				}
				hasKSign = true
			}

			if q.ValidTSign {
				if err := tSign.Deserialize(q.TSign.Serialize()); err != nil {
					return err
				}
				hasTSign = true
			}
		} else {
			if q.ValidKSign {
				kSign.Add(&q.KSign)
				hasKSign = true
			}

			if q.ValidTSign {
				tSign.Add(&q.TSign)
				hasTSign = true
			}
		}
		mask[q.Index>>3] |= 1 << uint64(q.Index%8)
	}

	v.qc[phase] = &QC{
		mask: mask,
	}

	if hasKSign {
		v.qc[phase].kSign = &kSign
	}

	if hasTSign {
		v.qc[phase].tSign = &tSign
	}

	return nil
}

func (hsm *HotstuffProtocolManager) lookupQuorum(pubKey *bls.PublicKey, quorum []*Quorum) bool {
	for _, q := range quorum {
		if q.PubKey.IsEqual(pubKey) {
			return true
		}
	}

	return false
}

// for leader
func (hsm *HotstuffProtocolManager) handleNewViewMsg(msg *HotstuffMessage) error {
	//start := time.Now()
	// defer func() {
		//	handleTime := time.Now().Sub(start).Nanoseconds() / 1000000
		//	log.Debug("handleNewViewMsg handle time", "ellpased", handleTime)
	// }()

	log.Info("handleNewViewMsg got new view message", "from", msg.Id, "viewId", msg.ViewId)
	err := hsm.app.CheckView(msg.DataA)
	if err == ErrOldState {
		log.Warn("check new view failed, discard", "viewID", msg.ViewId)
		return err
	}

	v, exist := hsm.lookupView(msg.ViewId)
	if !exist {
		v = hsm.createView(true, PhasePrepare, hsm.app.Self(), msg.DataA)
		log.Debug("create new view", "leader", v.leaderId, "viewID", v.hash)
		hsm.addView(v)
	}

	v.futureNewViewMsg = append(v.futureNewViewMsg, msg)
	if err == ErrFutureState {
		log.Warn("new view got future state ", "viewID", msg.ViewId)
		return err
	}

	hsm.updateViewPublicKey(v)

	for _, m := range v.futureNewViewMsg {
		err, qrum := v.msgToQuorum(m)
		if err != nil {
			log.Debug("New view message failed to convert to quorum", "error", err)
			continue
		}

		if !qrum.KSign.VerifyHash(qrum.PubKey, crypto.Keccak256(m.DataA)) {
			log.Debug("New view message failed to verify quorum")
			err = ErrQCVerification
			continue
		}

		if v.hash != m.ViewId {
			log.Debug("handleNewViewMsg got new-view message with un-matched view id", "from", m.Id, "viewId", m.ViewId)
			err = ErrViewIdNotMatch
			continue
		}

		// check if the new view is already received
		pubKey := bls.GetPublicKey(m.PubKey)
		if pubKey == nil {
			log.Debug("new-view message has invalid public key", "from", m.Id, "viewId", m.ViewId, "pubKey", hex.EncodeToString(m.PubKey))
			continue
		}
		/*
			var pubKey bls.PublicKey
			if err := pubKey.Deserialize(m.PubKey); err != nil {
				log.Debug("new-view message has invalid public key", "from", m.Id, "viewId", m.ViewId, "pubKey", hex.EncodeToString(m.PubKey))
				continue
			}
		*/
		if hsm.lookupQuorum(pubKey, v.highQuorum) {
			log.Warn("receive dup new-view meesage", "from", m.Id, "viewId", m.ViewId)
			continue
		}

		if v.phaseAsLeader != PhasePrepare {
			log.Debug("handleNewViewMsg view phase not match", "viewID", hex.EncodeToString(v.hash[:]), "phase", readablePhase(v.phaseAsLeader), "shouldBe", readablePhase(PhasePrepare))

			if prepareMsg, ok := v.leaderMsg[MsgPrepare]; ok {
				log.Debug("handleNewViewMsg load prepare message and send to replica", "replicaId", m.Id)
				hsm.app.Write(m.Id, prepareMsg)
			}

			continue
		}

		v.highQuorum = append(v.highQuorum, qrum)
		if len(v.currentState) != len(m.DataA) {
			v.currentState = make([]byte, len(m.DataA))
			copy(v.currentState, m.DataA)
		}

		if m.DataC != nil && len(m.DataC) > 0 {
			extra := make([]byte, len(m.DataC))
			copy(extra, m.DataC)

			v.extra = append(v.extra, extra)
		}
	}

	v.futureNewViewMsg = make([]*HotstuffMessage, 0)
	if v.phaseAsLeader != PhasePrepare {
		// this happens when leader receives more new-view messages than (2f + 1) threshold
		// the leader should write the Prepare message to these late replica too
		return nil
	}

	hsm.leaderView = v

	threshold := v.threshold + 1
	if threshold > len(v.groupPublicKey) {
		threshold = len(v.groupPublicKey)
	}

	if len(v.highQuorum) < threshold {
		log.Info("handleNewViewMsg need more quorum", "threshold", v.threshold, "current", len(v.highQuorum))
		return ErrInsufficientQC
	}

	v.phaseAsLeader = PhaseTryPropose
	elapsed := time.Now().Sub(v.createdAt).Nanoseconds() / 1000000

	log.Debug("on new view", "ViewId", v.hash, "timeElapsed", elapsed)

	// notify app the new view only when leader has (n - f) votes
	if err := hsm.app.OnNewView(v.currentState, v.extra); err != nil {
		log.Debug("New view message failed verification", "error", err)
		return err
	}

	hsm.lockView(v)

	return hsm.TryPropose()
}

func (hsm *HotstuffProtocolManager) TryPropose() error {
	v := hsm.leaderView
	if v == nil {
		return ErrInvalidLeaderView
	}

	if v.phaseAsLeader != PhaseTryPropose {
		log.Warn("TryPropose is not called on PhaseTryPropose stage, ignore", "viewId", v.hash, "phase", v.phaseAsLeader)
		return ErrViewPhaseNotMatch
	}

	err, kProposal, tProposal, extra := hsm.app.Propose()
	if err != nil {
		log.Warn("hotstuff application failed to propose")
		return err
	}

	if err := hsm.aggregateQC(v, "high", v.highQuorum); err != nil {
		log.Debug("aggregate high quorum failed")
		return err
	}

	msg := hsm.newMsg(MsgPrepare, v.hash, kProposal, tProposal, v.qc["high"].kSign.Serialize())
	msg.DataD = make([]byte, len(v.qc["high"].mask))
	copy(msg.DataD, v.qc["high"].mask)

	msg.DataE = make([]byte, len(v.currentState))
	copy(msg.DataE, v.currentState)

	if extra != nil && len(extra) > 0 {
		msg.DataF = make([]byte, len(extra))
		copy(msg.DataF, extra)
	}

	log.Debug("view broadcast Prepare msg", "viewID", v.hash)
	hsm.app.Broadcast(msg)
	v.leaderMsg[MsgPrepare] = msg

	if kProposal != nil && len(kProposal) > 0 {
		v.proposedKState = make([]byte, len(kProposal))
		copy(v.proposedKState, kProposal)
	}

	if tProposal != nil && len(tProposal) > 0 {
		v.proposedTState = make([]byte, len(tProposal))
		copy(v.proposedTState, tProposal)
	}

	v.phaseAsLeader = PhasePreCommit
	hsm.leaderView = nil

	hsm.DumpView(v, true)
	return nil
}

func VerifySignature(bSign []byte, bMask []byte, data []byte, groupPublicKey []*bls.PublicKey) bool {
	var sign bls.Sign
	if err := sign.Deserialize(bSign); err != nil {
		return false
	}

	isFirst := true
	var pub bls.PublicKey

	signer := 0

loop:
	for i := range bMask {
		for bit := 0; bit < 8; bit++ {
			if i*8+bit >= len(groupPublicKey) {
				break loop
			}

			if bMask[i]&(1<<uint64(bit)) != 0 {
				if isFirst {
					pub.Deserialize(groupPublicKey[i*8+bit].Serialize())
					isFirst = false
				} else {
					pub.Add(groupPublicKey[i*8+bit])
				}

				signer += 1
			}
		}
	}

	if (signer < CalcThreshold(len(groupPublicKey))) || !sign.VerifyHash(&pub, crypto.Keccak256(data)) {
		log.Debug("Dump failed signature ================")
		log.Debug("signer", "is", signer, "threshold", CalcThreshold(len(groupPublicKey)))
		log.Debug("Signature", "is ", hex.EncodeToString(bSign))
		log.Debug("Mask     ", "is ", hex.EncodeToString(bMask))
		log.Debug("Data     ", "is ", hex.EncodeToString(data))

		for i, p := range groupPublicKey {
			log.Debug("Public Key", "index", i, "key", hex.EncodeToString(p.Serialize()))
		}

		log.Debug("Dump failed signature end =================>>")
		return false
	}

	return true
}

func MaskToException(bMask []byte, groupPublicKey []*bls.PublicKey) []*bls.PublicKey {
	exception := make([]*bls.PublicKey, 0)
loop:
	for i := range bMask {
		for bit := 0; bit < 8; bit++ {
			if i*8+bit >= len(groupPublicKey) {
				break loop
			}

			if bMask[i]&(byte)(1<<(uint)(bit)) != 0 {
				exception = append(exception, groupPublicKey[i*8+bit])
			}
		}
	}

	return exception
}

// for replica
func (hsm *HotstuffProtocolManager) handlePrepareMsg(m *HotstuffMessage) error {
	v, exist := hsm.lookupView(m.ViewId)
	if !exist {
		v = hsm.createView(false, PhasePrepare, hsm.app.Self(), m.DataE)
		hsm.addView(v)
		log.Debug("handlePrepareMsg create view", "viewId", m.ViewId)
	}

	if v.phaseAsReplica != PhasePrepare {
		log.Trace("handlePrepareMsg discard old-phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		//fmt.Println("handlePrepareMsg discard old-phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		return ErrViewPhaseNotMatch
	}

	var kState, tState, extra []byte
	if len(m.DataA) > 0 {
		kState = m.DataA
	}

	if len(m.DataB) > 0 {
		tState = m.DataB
	}

	if len(m.DataF) > 0 {
		extra = m.DataF
	}

	// verify highQC in the prepare msg
	if !VerifySignature(m.DataC, m.DataD, m.DataE, v.groupPublicKey) {
		log.Debug("handlePrepareMsg failed to verify highQC", "viewId", m.ViewId)
		return ErrInvalidHighQC
	}

	if err := hsm.app.OnPropose(kState, tState, extra); err != nil {
		log.Debug("handlePrepareMsg failed to verify proposed data", "viewId", m.ViewId)
		return ErrInvalidProposal
	}

	hsm.lockView(v)

	kSign := []byte(nil)
	tSign := []byte(nil)

	if m.DataA != nil && len(m.DataA) > 0 {
		v.proposedKState = make([]byte, len(m.DataA))
		copy(v.proposedKState, m.DataA)

		kSign = hsm.secretKey.SignHash(crypto.Keccak256(v.proposedKState)).Serialize()
	}

	if m.DataB != nil && len(m.DataB) > 0 {
		v.proposedTState = make([]byte, len(m.DataB))
		copy(v.proposedTState, m.DataB)

		tSign = hsm.secretKey.SignHash(crypto.Keccak256(v.proposedTState)).Serialize()
	}

	msg := hsm.newMsg(MsgVotePrepare, v.hash, nil, kSign, tSign)

	log.Debug("handlePrepareMsg send VotePrepare msg", "viewID", v.hash)
	hsm.app.Write(m.Id, msg)
	v.phaseAsReplica = PhaseDecide

	return nil
}

func (hsm *HotstuffProtocolManager) createSignatureMsg(v *View, code uint64, phase string) *HotstuffMessage {
	bKSign := []byte(nil)
	bTSign := []byte(nil)
	if v.qc[phase].kSign != nil {
		bKSign = v.qc[phase].kSign.Serialize()
	}
	if v.qc[phase].tSign != nil {
		bTSign = v.qc[phase].tSign.Serialize()
	}

	// DataA: kSign, DataB: tSign, DataC: mask
	return hsm.newMsg(code, v.hash, bKSign, bTSign, v.qc[phase].mask)
}

// for leader
func (hsm *HotstuffProtocolManager) handlePrepareVoteMsg(m *HotstuffMessage) error {
	v, exist := hsm.lookupView(m.ViewId)
	if !exist {
		log.Debug("handlePrepareVoteMsg found no matched view", "viewId", m.ViewId)
		return ErrMissingView
	}

	err, qrum := v.msgToQuorum(m)
	if err != nil {
		log.Debug("handlePrepareVoteMsg failed to convert msg to quorum", "error", err)
		return err
	}

	if v.hasKState() {
		if !qrum.ValidKSign || !qrum.KSign.VerifyHash(qrum.PubKey, crypto.Keccak256(v.proposedKState)) {
			log.Debug("handlePrepareVoteMsg failed to verify k-state signature", "viewId", m.ViewId)
			return ErrQCVerification
		}
	}

	if v.hasTState() {
		if !qrum.ValidTSign || !qrum.TSign.VerifyHash(qrum.PubKey, crypto.Keccak256(v.proposedTState)) {
			log.Debug("handlePrepareVoteMsg failed to verify t-state signature", "viewId", m.ViewId)
			hsm.DumpView(v, true)
			return ErrQCVerification
		}
	}

	if v.phaseAsLeader != PhasePreCommit {
		log.Trace("handlePrepareVoteMsg view phase not match", "viewID", hex.EncodeToString(v.hash[:]), "phase", readablePhase(v.phaseAsLeader), "shouldBe", readablePhase(PhasePreCommit))

		if preCommitMsg, ok := v.leaderMsg[MsgPreCommit]; ok {
			log.Debug("handlePrepareVoteMsg load PreCommit message and send to replica", "replicaId", m.Id)
			hsm.app.Write(m.Id, preCommitMsg)

			return nil
		}

		return ErrViewPhaseNotMatch
	}
	pubKey := bls.GetPublicKey(m.PubKey)
	if pubKey == nil {
		log.Warn("prepare-vote message has invalid public key", "from", m.Id, "viewId", m.ViewId, "pubKey", hex.EncodeToString(m.PubKey))
		return nil
	}
	/*
		var pubKey bls.PublicKey
		if err := pubKey.Deserialize(m.PubKey); err != nil {
			log.Warn("prepare-vote message has invalid public key", "from", m.Id, "viewId", m.ViewId, "pubKey", hex.EncodeToString(m.PubKey))
			return nil
		}
	*/
	if hsm.lookupQuorum(pubKey, v.prepareQuorum) {
		log.Warn("discard dup prepare-vote message", "from", m.Id, "viewId", m.ViewId)
		return nil
	}

	v.prepareQuorum = append(v.prepareQuorum, qrum)
	if len(v.prepareQuorum) < v.threshold {
		log.Debug("handlePrepareVoteMsg need more quorum", "threshold", v.threshold, "current", len(v.prepareQuorum))
		return ErrInsufficientQC
	}

	log.Debug("handlePrepareVoteMsg collect sufficient votes", "viewId", m.ViewId)

	if err := hsm.aggregateQC(v, "prepare", v.prepareQuorum); err != nil {
		log.Debug("aggregate prepare quorum failed")
		return err
	}

	msg := hsm.createSignatureMsg(v, MsgDecide, "prepare")

	log.Debug("handlePrepareVoteMsg broadcast Decide msg", "viewId", m.ViewId)
	hsm.app.Broadcast(msg)
	v.phaseAsLeader = PhaseFinal
	v.leaderMsg[MsgDecide] = msg

	return nil
}

// for replica
func (hsm *HotstuffProtocolManager) handlePreCommitMsg(m *HotstuffMessage) error {
	v, exist := hsm.lookupView(m.ViewId)
	if !exist {
		log.Trace("handlePreCommitMsg found no match view", "viewId", m.ViewId)
		return ErrUnhandledMsg
	}

	if v.phaseAsReplica < PhasePreCommit {
		log.Debug("handlePreCommitMsg got future phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		return ErrUnhandledMsg
	}

	if v.phaseAsReplica > PhasePreCommit {
		log.Debug("handlePreCommitMsg discard old phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		return ErrViewOldPhase
	}

	// verify prepareQC in the prepare msg
	if v.hasKState() {
		if !VerifySignature(m.DataA, m.DataC, v.proposedKState, v.groupPublicKey) {
			log.Debug("handlePreCommitMsg failed to verify aggregated k-state signature", "viewId", m.ViewId)
			return ErrInvalidPrepareQC
		}
	}

	if v.hasTState() {
		if !VerifySignature(m.DataB, m.DataC, v.proposedTState, v.groupPublicKey) {
			log.Debug("handlePreCommitMsg failed to verify aggregated t-state signature", "viewId", m.ViewId)
			hsm.DumpView(v, false)
			return ErrInvalidPrepareQC
		}
	}

	// todo save prepareQC

	kSign := []byte(nil)
	tSign := []byte(nil)
	if v.hasKState() {
		kSign = hsm.secretKey.SignHash(crypto.Keccak256(v.proposedKState)).Serialize()
	}

	if v.hasTState() {
		tSign = hsm.secretKey.SignHash(crypto.Keccak256(v.proposedTState)).Serialize()
	}

	msg := hsm.newMsg(MsgVotePreCommit, v.hash, nil, kSign, tSign)

	log.Debug("handlePreCommitMsg send PhaseCommit msg", "viewId", v.hash)
	hsm.app.Write(m.Id, msg)
	v.phaseAsReplica = PhaseCommit

	return nil
}

// for leader
func (hsm *HotstuffProtocolManager) handlePreCommitVoteMsg(m *HotstuffMessage) error {
	v, exist := hsm.lookupView(m.ViewId)
	if !exist {
		log.Trace("handlePreCommitVoteMsg found no match view", "viewId", m.ViewId)
		return ErrMissingView
	}

	err, qrum := v.msgToQuorum(m)
	if err != nil {
		log.Debug("handlePreCommitVoteMsg failed to convert msg to quorum", "error", err)
		return err
	}

	if v.hasKState() {
		if !qrum.ValidKSign || !qrum.KSign.VerifyHash(qrum.PubKey, crypto.Keccak256(v.proposedKState)) {
			log.Debug("handlePreCommitVoteMsg failed to verify k-state signature", "viewId", m.ViewId)
			return ErrQCVerification
		}
	}

	if v.hasTState() {
		if !qrum.ValidTSign || !qrum.TSign.VerifyHash(qrum.PubKey, crypto.Keccak256(v.proposedTState)) {
			log.Debug("handlePreCommitVoteMsg failed to verify t-state signature", "viewId", m.ViewId)
			hsm.DumpView(v, true)
			return ErrQCVerification
		}
	}

	if v.phaseAsLeader != PhaseCommit {
		log.Trace("handlePreCommitVoteMsg view phase not match", "viewID", hex.EncodeToString(v.hash[:]), "phase", readablePhase(v.phaseAsLeader), "shouldBe", readablePhase(PhaseCommit))

		if commitMsg, ok := v.leaderMsg[MsgCommit]; ok {
			log.Debug("handlePreCommitVoteMsg load commit message and send to replica", "replicaId", m.Id)
			hsm.app.Write(m.Id, commitMsg)

			return nil
		}

		return ErrViewPhaseNotMatch
	}
	pubKey := bls.GetPublicKey(m.PubKey)
	if pubKey == nil {
		log.Warn("pre-commit message has invalid public key", "from", m.Id, "viewId", m.ViewId, "pubKey", hex.EncodeToString(m.PubKey))
		return nil
	}
	/*
		var pubKey bls.PublicKey
		if err := pubKey.Deserialize(m.PubKey); err != nil {
			log.Warn("pre-commit message has invalid public key", "from", m.Id, "viewId", m.ViewId, "pubKey", hex.EncodeToString(m.PubKey))
			return nil
		}
	*/
	if hsm.lookupQuorum(pubKey, v.preCommitQuorum) {
		log.Warn("discard dup pre-commit message", "from", m.Id, "viewId", m.ViewId)
		return nil
	}

	v.preCommitQuorum = append(v.preCommitQuorum, qrum)
	if len(v.preCommitQuorum) < v.threshold {
		log.Debug("handlePreCommitVoteMsg need more quorum", "threshold", v.threshold, "current", len(v.preCommitQuorum))
		return ErrInsufficientQC
	}

	if err := hsm.aggregateQC(v, "preCommit", v.preCommitQuorum); err != nil {
		log.Debug("aggregate preCommit quorum failed")
		return err
	}

	msg := hsm.createSignatureMsg(v, MsgCommit, "preCommit")

	log.Debug("handlePreCommitVoteMsg broadcast Commit msg", "viewId", m.ViewId)
	hsm.app.Broadcast(msg)
	v.phaseAsLeader = PhaseDecide
	v.leaderMsg[MsgCommit] = msg

	return nil
}

// for replica
func (hsm *HotstuffProtocolManager) handleCommitMsg(m *HotstuffMessage) error {
	v, exist := hsm.lookupView(m.ViewId)
	if !exist {
		log.Trace("handleCommitMsg found no match view", "viewId", m.ViewId)
		return ErrUnhandledMsg
	}

	if v.phaseAsReplica < PhaseCommit {
		log.Debug("handleCommitMsg got future phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		return ErrUnhandledMsg
	}

	if v.phaseAsReplica > PhaseCommit {
		log.Debug("handleCommitMsg discard old phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		//fmt.Println("handleCommitMsg discard old phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		return ErrViewOldPhase
	}

	// verify pre-commitQC in the commit msg
	if v.hasKState() {
		if !VerifySignature(m.DataA, m.DataC, v.proposedKState, v.groupPublicKey) {
			log.Debug("handleCommitMsg failed to verify aggregated k-state signature", "viewId", m.ViewId)
			return ErrInvalidPrepareQC
		}
	}

	if v.hasTState() {
		if !VerifySignature(m.DataB, m.DataC, v.proposedTState, v.groupPublicKey) {
			log.Debug("handleCommitMsg failed to verify aggregated t-state signature", "viewId", m.ViewId)
			hsm.DumpView(v, false)
			return ErrInvalidPrepareQC
		}
	}

	// todo: save commitQC as lockedQC
	kSign := []byte(nil)
	tSign := []byte(nil)
	if v.hasKState() {
		kSign = hsm.secretKey.SignHash(crypto.Keccak256(v.proposedKState)).Serialize()
	}

	if v.hasTState() {
		tSign = hsm.secretKey.SignHash(crypto.Keccak256(v.proposedTState)).Serialize()
	}

	msg := hsm.newMsg(MsgVoteCommit, v.hash, nil, kSign, tSign)

	log.Debug("handleCommitMsg send VoteCommit msg", "viewId", v.hash)
	hsm.app.Write(m.Id, msg)
	v.phaseAsReplica = PhaseDecide

	return nil
}

// for leader
func (hsm *HotstuffProtocolManager) handleCommitVoteMsg(m *HotstuffMessage) error {
	v, exist := hsm.lookupView(m.ViewId)
	if !exist {
		log.Trace("handleCommitVoteMsg found no match view", "viewId", m.ViewId)
		return ErrMissingView
	}

	err, qrum := v.msgToQuorum(m)
	if err != nil {
		log.Debug("handleCommitVoteMsg failed to convert msg to quorum", "error", err)
		return err
	}

	if v.hasKState() {
		if !qrum.ValidKSign || !qrum.KSign.VerifyHash(qrum.PubKey, crypto.Keccak256(v.proposedKState)) {
			log.Debug("handleCommitVoteMsg failed to verify k-state signature", "viewId", m.ViewId)
			return ErrQCVerification
		}
	}

	if v.hasTState() {
		if !qrum.ValidTSign || !qrum.TSign.VerifyHash(qrum.PubKey, crypto.Keccak256(v.proposedTState)) {
			log.Debug("handleCommitVoteMsg failed to verify t-state signature", "viewId", m.ViewId)
			hsm.DumpView(v, true)
			return ErrQCVerification
		}
	}

	if v.phaseAsLeader != PhaseDecide {
		log.Trace("handleCommitVoteMsg view phase not match", "viewID", hex.EncodeToString(v.hash[:]), "phase", readablePhase(v.phaseAsLeader), "shouldBe", readablePhase(PhaseDecide))

		if decideMsg, ok := v.leaderMsg[MsgDecide]; ok {
			log.Debug("handleCommitVoteMsg load decide message and send to replica", "replicaId", m.Id)
			hsm.app.Write(m.Id, decideMsg)

			return nil
		}

		return ErrViewPhaseNotMatch
	}
	pubKey := bls.GetPublicKey(m.PubKey)
	if pubKey == nil {
		log.Warn("commit message has invalid public key", "from", m.Id, "viewId", m.ViewId, "pubKey", hex.EncodeToString(m.PubKey))
		return nil
	}
	/*
		var pubKey bls.PublicKey
		if err := pubKey.Deserialize(m.PubKey); err != nil {
			log.Warn("commit message has invalid public key", "from", m.Id, "viewId", m.ViewId, "pubKey", hex.EncodeToString(m.PubKey))
			return nil
		}
	*/
	if hsm.lookupQuorum(pubKey, v.commitQuorum) {
		log.Warn("discard dup commit message", "from", m.Id, "viewId", m.ViewId)
		return nil
	}

	v.commitQuorum = append(v.commitQuorum, qrum)
	if len(v.commitQuorum) < v.threshold {
		log.Debug("handleCommitVoteMsg need more quorum", "threshold", v.threshold, "current", len(v.commitQuorum))
		return ErrInsufficientQC
	}

	if err := hsm.aggregateQC(v, "commit", v.commitQuorum); err != nil {
		log.Debug("aggregate commit quorum failed", "viewId", v.hash)
		return err
	}

	msg := hsm.createSignatureMsg(v, MsgDecide, "commit")

	log.Debug("handleCommitVoteMsg broadcast Decide msg", "viewId", m.ViewId)
	hsm.app.Broadcast(msg)
	v.phaseAsLeader = PhaseFinal
	v.leaderMsg[MsgDecide] = msg

	return nil
}

// for replica
func (hsm *HotstuffProtocolManager) handleDecideMsg(m *HotstuffMessage) error {
	v, exist := hsm.lookupView(m.ViewId)
	if !exist {
		log.Trace("handleDecideMsg found no match view", "viewId", m.ViewId)
		return ErrUnhandledMsg
	}

	if v.phaseAsReplica < PhaseDecide {
		log.Debug("handleDecideMsg got future phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		return ErrUnhandledMsg
	}

	if v.phaseAsReplica > PhaseDecide {
		log.Trace("handleDecideMsg discard old phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		return ErrViewOldPhase
	}

	// verify commitQC in the decide phase
	if v.hasKState() {
		if !VerifySignature(m.DataA, m.DataC, v.proposedKState, v.groupPublicKey) {
			log.Debug("handleDecideMsg failed to verify aggregated k-state signature", "viewId", m.ViewId)
			return ErrInvalidPrepareQC
		}
	}

	if v.hasTState() {
		if !VerifySignature(m.DataB, m.DataC, v.proposedTState, v.groupPublicKey) {
			log.Debug("handleDecideMsg failed to verify aggregated t-state signature", "viewId", m.ViewId)
			hsm.DumpView(v, false)
			return ErrInvalidPrepareQC
		}
	}

	log.Debug("handleDecideMsg view done", "viewId", m.ViewId)

	// execute the command
	hsm.viewDone(v, m.DataA, m.DataB, m.DataC, nil)
	v.phaseAsReplica = PhaseFinal

	// start new view
	//hsm.NewView()

	return nil
}

func (hsm *HotstuffProtocolManager) NewViewMessage() *HotstuffMessage {
	return hsm.newMsg(MsgStartNewView, common.Hash{}, nil, nil, nil)
}

func (hsm *HotstuffProtocolManager) TryProposeMessage() *HotstuffMessage {
	return hsm.newMsg(MsgTryPropose, common.Hash{}, nil, nil, nil)
}

func (hsm *HotstuffProtocolManager) handleStartNewView() error {
	log.Debug("handler handleStartNewView")
	return hsm.NewView()
}

func (hsm *HotstuffProtocolManager) handlerTryPropose() error {
	//log.Debug("handler MsgTryPropose")
	return hsm.TryPropose()
}

func (hsm *HotstuffProtocolManager) Stop() {
	select {
	case hsm.exit <- true:
	default:
	}
}

func (hsm *HotstuffProtocolManager) handleViewTimeout() error {
	now := time.Now()
	for _, v := range hsm.views {
		duration := now.Sub(v.createdAt).Seconds()

		if duration > hsm.timeout.Seconds() {
			log.Debug("Remove timeout view", "viewId", v.hash, "phase", readablePhase(v.phaseAsReplica))
			if v.phaseAsReplica < PhaseFinal {
				hsm.viewDone(v, nil, nil, nil, ErrViewTimeout)
			}

			hsm.removeView(v)
		}
	}

	for k, m := range hsm.unhandledMsg {
		duration := now.Sub(m.ReceivedAt).Seconds()

		if duration > hsm.timeout.Seconds() {
			log.Debug("Remove unhandled hotstuff message", "viewId", m.ViewId, "code", m.Code, "from", m.Id)
			hsm.removeFromUnhandled(k)
		}
	}

	return nil
}

func (hsm *HotstuffProtocolManager) setTimeoutTicker(d time.Duration) {
	hsm.tickerPeriod = d
}

func (hsm *HotstuffProtocolManager) collectTimeoutView() {
	ticker := time.NewTicker(hsm.tickerPeriod)
	for {
		select {
		case <-hsm.exit:
			ticker.Stop()
			return
		case <-ticker.C:
			hsm.app.Write(hsm.app.Self(), hsm.newMsg(MsgCollectTimeoutView, common.Hash{}, nil, nil, nil))
		}
	}
}

func (hsm *HotstuffProtocolManager) handleMessage(m *HotstuffMessage) error {
	switch {
	case m.Code == MsgNewView:
		return hsm.handleNewViewMsg(m)

	case m.Code == MsgPrepare:
		return hsm.handlePrepareMsg(m)
	case m.Code == MsgVotePrepare:
		return hsm.handlePrepareVoteMsg(m)

	case m.Code == MsgPreCommit:
		return hsm.handlePreCommitMsg(m)
	case m.Code == MsgVotePreCommit:
		return hsm.handlePreCommitVoteMsg(m)

	case m.Code == MsgCommit:
		return hsm.handleCommitMsg(m)
	case m.Code == MsgVoteCommit:
		return hsm.handleCommitVoteMsg(m)

	case m.Code == MsgDecide:
		return hsm.handleDecideMsg(m)

	case m.Code == MsgCollectTimeoutView:
		return hsm.handleViewTimeout()
	case m.Code == MsgStartNewView:
		return hsm.handleStartNewView()
	case m.Code == MsgTryPropose:
		return hsm.handlerTryPropose()

	default:
		log.Warn("unknown hotstuff message", "code", m.Code)
		return nil
	}
}

func (hsm *HotstuffProtocolManager) addToUnhandled(m *HotstuffMessage) {
	bs, err := rlp.EncodeToBytes(m)
	if err != nil {
		log.Warn("failed to encode hotstuff message to bytes, discarded")
		return
	}
	m.touch()

	k := crypto.Keccak256Hash(bs)
	hsm.unhandledMsg[k] = m
}

func (hsm *HotstuffProtocolManager) removeFromUnhandled(k common.Hash) {
	delete(hsm.unhandledMsg, k)
}

func (hsm *HotstuffProtocolManager) HandleMessage(msg *HotstuffMessage) error {
	err := hsm.handleMessage(msg)
	if err == ErrUnhandledMsg {
		log.Debug("Add unhandled hotstuff message", "viewId", msg.ViewId, "code", msg.Code, "from", msg.Id)
		//fmt.Println("Add unhandled hotstuff message", "viewId", msg.ViewId, "code", msg.Code, "from", msg.Id)
		hsm.addToUnhandled(msg)
		return ErrUnhandledMsg
	}

	for k, m := range hsm.unhandledMsg {
		if e := hsm.handleMessage(m); e != ErrUnhandledMsg {
			log.Debug("Remove unhandled hotstuff message", "viewId", msg.ViewId, "code", msg.Code, "from", msg.Id)
			hsm.removeFromUnhandled(k)
		}
	}

	return err
}
