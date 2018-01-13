package darc

import (
	"testing"
	"fmt"
	"encoding/json"

//	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/onet.v1/log"
)

func TestDarc(t *testing.T) {
	var rules []*Rule
	for i := 0; i < 2; i++ {
		rules = append(rules, createRule().rule)
	}
	d := NewDarc(&rules)
	for i, rule := range rules {
		require.Equal(t, *rule, *(*d.Rules)[i])
	}
}

func TestDarc_Copy(t *testing.T) {
	d1 := createDarc().darc
	d2 := d1.Copy()
	d1.Version = 3
	d1.AddRule(createRule().rule)
	require.NotEqual(t, len(*d1.Rules), len(*d2.Rules))
	require.NotEqual(t, d1.Version, d2.Version)
	d2 = d1.Copy()
	require.Equal(t, d1.GetID(), d2.GetID())
	require.Equal(t, len(*d1.Rules), len(*d2.Rules))
}

func TestDarc_AddRule(t *testing.T) {
	d := createDarc().darc
	rule := createRule().rule
	d.AddRule(rule)
	require.Equal(t, rule, (*d.Rules)[len(*d.Rules)-1])
}

func TestDarc_RemoveRule(t *testing.T) {
	d1 := createDarc().darc
	d2 := d1.Copy()
	rule := createRule().rule
	d2.AddRule(rule)
	require.NotEqual(t, len(*d1.Rules), len(*d2.Rules))
	d2.RemoveRule(len(*d2.Rules)-1)
	require.Equal(t, len(*d1.Rules), len(*d2.Rules))
}

func TestDarc_RuleUpdateAction(t *testing.T) {
	d1 := createDarc().darc
	rule := createRule().rule
	d1.AddRule(rule)
	d2 := d1.Copy()
	ind1 := len(*d1.Rules)-1
	ind2 := len(*d2.Rules)-1
	require.Equal(t, (*d1.Rules)[ind1].Action, (*d2.Rules)[ind2].Action)
	action := string("TestUpdate")
	d2.RuleUpdateAction(ind2, action)
	require.NotEqual(t, (*d1.Rules)[ind1].Action, (*d2.Rules)[ind2].Action)
}

func TestDarc_RuleAddSubject(t *testing.T) {
	d := createDarc().darc
	s := createSubject_PK()
	d.RuleAddSubject(0, s)
	ind := len(*(*d.Rules)[0].Subjects)-1
	r1 := (*d.Rules)[0]
	s1 := (*r1.Subjects)[ind]
	require.Equal(t, s, s1)
}

func TestDarc_RuleRemoveSubject(t *testing.T) {
	d1 := createDarc().darc
	d2 := d1.Copy()
	s := createSubject_PK()
	d2.RuleAddSubject(0, s)
	require.NotEqual(t, len(*(*d1.Rules)[0].Subjects), len(*(*d2.Rules)[0].Subjects))
	d2.RuleRemoveSubject(0, s)
	require.Equal(t, len(*(*d1.Rules)[0].Subjects), len(*(*d2.Rules)[0].Subjects))
}

func TestDarc_RuleUpdateExpression(t *testing.T) {
	d1 := createDarc().darc
	rule := createRule().rule
	d1.AddRule(rule)
	d2 := d1.Copy()
	ind := len(*d2.Rules)-1
	require.Equal(t, (*d1.Rules)[ind].Expression, (*d2.Rules)[ind].Expression)
	d2.RuleUpdateExpression(ind, `{"or" : [0,1]}`)
	require.NotEqual(t, (*d1.Rules)[ind].Expression, (*d2.Rules)[ind].Expression)
}

func TestRequest_Copy(t *testing.T) {
	req, _ := createRequest()
	req1 := req.request
	req2 := req1.CopyReq()
	req1.RuleID = 1000
	require.NotEqual(t, req1.RuleID, req2.RuleID)
	require.Equal(t, req1.DarcID, req2.DarcID)
	require.Equal(t, req1.Requester, req2.Requester)
	req2 = req1.CopyReq()
	require.Equal(t, req1.RuleID, req2.RuleID)
}

func TestRequest_Sign(t *testing.T) {
	r, signer := createRequest()
	req := r.request
	_, err := signer.Sign(req)
	if err != nil {
		log.ErrFatal(err)
	}
	//fmt.Println("Signature:", sig.Signature)
}

func TestRequest_Verify(t *testing.T) {
	req, signer := createRequest2()
	sig, err := signer.Sign(req.request)
	if err != nil {
		log.ErrFatal(err)
	}
	err = Verify(req.request, sig, darcMap)
	if err != nil {
		fmt.Println(err)
	} else {
		var raw interface{}
    	json.Unmarshal(req.request.Message, &raw)
		fmt.Println("Single-sig Verification works")
	}
}

func TestRequestMultiSig_Verify(t *testing.T) {
	req, signers := createRequestMultiSig()
	var signatures []*Signature
	for _, signer := range signers {
		sig, err := signer.Sign(req.request)
		if err != nil {
			log.ErrFatal(err)
		}
		signatures = append(signatures, sig)
	}
	err := VerifyMultiSig(req.request, signatures, darcMap)
	if err != nil {
		fmt.Println(err)
	} else {
		var raw interface{}
    	json.Unmarshal(req.request.Message, &raw)
		fmt.Println("Multi-sig Verification works")
	}
}

func TestDarc_IncrementVersion(t *testing.T) {
	d := createDarc().darc
	previousVersion := d.Version
	d.IncrementVersion()
	require.NotEqual(t, previousVersion, d.Version)
}

var darcMap = make(map[string]*Darc)

type testDarc struct {
	darc *Darc
	rules []*Rule
}

type testRule struct {
	rule *Rule
	subjects []*Subject
}

type testRequest struct {
	request *Request
}

func createDarc() *testDarc {
	td := &testDarc{}
	r := createAdminRule()
	td.rules = append(td.rules, r.rule)
	td.darc = NewDarc(&td.rules)
	darcMap[string(td.darc.GetID())] = td.darc
	return td
}

func createAdminRule() *testRule {
	tr := &testRule{}
	action := "Admin"
	expression := `{"and" : [0, 1]}`
	for i := 0; i < 3; i++ {
		s := createSubject_PK()
		tr.subjects = append(tr.subjects, s)
	}
	tr.rule = &Rule{Action: action, Subjects: &tr.subjects, Expression: expression}
	return tr
}

func createRule() *testRule {
	tr := &testRule{}
	action := "Read"
	expression := `{}`
	s1 := createSubject_PK()
	s2 := createSubject_Darc()
	tr.subjects = append(tr.subjects, s1)
	tr.subjects = append(tr.subjects, s2)
	tr.rule = &Rule{Action: action, Subjects: &tr.subjects, Expression: expression}
	return tr
}

func createSubject_Darc() *Subject {
	rule := createAdminRule().rule
	var rules []*Rule
	rules = append(rules, rule)
	darc := NewDarc(&rules)
	id := darc.GetID()
	darcMap[string(id)] = darc
	subjectdarc := NewSubjectDarc(id)
	subject, _ := NewSubject(subjectdarc, nil)
	return subject
}

func createSubject_PK() *Subject {
	_, subject := createSignerSubject()
	return subject
}

func createSigner() *Signer {
	signer, _ := createSignerSubject()
	return signer
}

func createSignerSubject() (*Signer, *Subject) {
	edSigner := NewEd25519Signer(nil, nil)
	signer := &Signer{Ed25519: edSigner}
	subjectpk := NewSubjectPK(signer.Ed25519.Point)
	subject, err := NewSubject(nil, subjectpk)
	log.ErrFatal(err)
	return signer, subject
}

func createRequest() (*testRequest, *Signer) {
	tr := &testRequest{}
	dr := createDarc().darc
	dr_id := dr.GetID()
	sig, sub := createSignerSubject()
	dr.RuleAddSubject(0, sub)
	msg, _ := json.Marshal("Document1")
	request := NewRequest(dr_id, 0, sub, msg)
	tr.request = request
	return tr, sig
}

func createRequest2() (*testRequest, *Signer) {
	tr := &testRequest{}
	dr := createDarc().darc
	dr_id := dr.GetID()
	sub1 := createSubject_Darc()
	dr.RuleAddSubject(0, sub1)
	dr2 := darcMap[string(sub1.Darc.ID)]
	sig, sub := createSignerSubject()
	dr2.RuleAddSubject(0, sub)
	msg, _ := json.Marshal("Document1")
	request := NewRequest(dr_id, 0, sub, msg)
	tr.request = request
	return tr, sig
}

func createRequestMultiSig() (*testRequest, []*Signer) {
	tr := &testRequest{}
	dr := createDarc().darc
	dr_id := dr.GetID()
	var requester *Subject
	var signers []*Signer
	for i := 0; i < 2; i++ {
		sig, sub := createSignerSubject()
		dr.RuleAddSubject(0, sub)
		requester = sub
		signers = append(signers, sig)
	}
	dr.RuleUpdateExpression(0, `{"and" : [3, 4]}`)
	msg, _ := json.Marshal(createDarc().darc)
	request := NewRequest(dr_id, 0, requester, msg)
	tr.request = request
	return tr, signers
}