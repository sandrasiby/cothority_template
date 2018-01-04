package darc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/onet.v1/log"
)

func TestDarc(t *testing.T) {
	var rules []*Rule
	for i := 0; i < 2; i++ {
		rules = append(rules, createRule())
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
	d1.AddRule(createRule())
	require.NotEqual(t, len(*d1.Rules), len(*d2.Rules))
	require.NotEqual(t, d1.Version, d2.Version)
	d2 = d1.Copy()
	require.Equal(t, d1.GetID(), d2.GetID())
}

func TestDarc_AddRule(t *testing.T) {
	d := createDarc().darc
	rule := createRule()
	d.AddRule(rule)
	require.Equal(t, rule, (*d.Rules)[len(*d.Rules)-1])
}

func TestDarc_RemoveRule(t *testing.T) {
	d1 := createDarc().darc
	d2 := d1.Copy()
	rule := createRule()
	d2.AddRule(rule)
	require.NotEqual(t, len(*d1.Rules), len(*d2.Rules))
	d2.RemoveRule(len(*d2.Rules)-1)
	require.Equal(t, len(*d1.Rules), len(*d2.Rules))
}

func TestDarc_RuleUpdateAction(t *testing.T) {
	d1 := createDarc().darc
	rule := createRule()
	d1.AddRule(rule)
	d2 := d1.Copy()
	ind := len(*d2.Rules)-1
	require.Equal(t, *d1.Rules[ind].Action, *d2.Rules[ind].Action)
	d2.RuleUpdateAction(l, "TestUpdate")
	require.NotEqual(t, (*d1.Rules)[ind].Action, (*d2.Rules)[ind].Action)
}

func TestDarc_RuleAddSubject(t *testing.T) {
	d := createDarc().darc
	s := createSubject_PK()
	d.RuleAddSubject(0, s)
	ind := len((*d.Rules)[0].Subjects)-1
	require.Equal(t, s, (*d.Rules)[0].Subjects[ind])
}

func TestDarc_RuleRemoveSubject(t *testing.T) {
	d1 := createDarc().darc
	d2 := d1.Copy()
	s := createSubject_PK()
	d2.RuleAddSubject(0, s)
	require.NotEqual(t, len(*d1.Rules[0].Subjects), len(*d2.Rules[0].Subjects))
	d2.RuleRemoveSubject(0, s)
	require.Equal(t, len(*d1.Rules[0].Subjects), len(*d2.Rules[0].Subjects))
}

func TestDarc_RuleUpdateExpression(t *testing.T) {
	d1 := createDarc().darc
	rule := createRule()
	d1.AddRule(rule)
	d2 := d1.Copy()
	ind := len(*d2.Rules)-1
	require.Equal(t, *d1.Rules[ind].Expression, *d2.Rules[ind].Expression)
	d2.RuleUpdateExpression(l, `{"or" : [0,1]}`)
	require.NotEqual(t, *d1.Rules[ind].Expression, *d2.Rules[ind].Expression)
}

func TestRequest_Copy(t *testing.T) {
	req1, _ := createRequest()
	req2 := req1.CopyReq()
	req1.RuleID = 1000
	require.NotEqual(t, req1.RuleID, req2.RuleID)
	require.Equal(t, req1.DarcID, req2.DarcID)
	require.Equal(t, req1.Requester, req2.Requester)
	req2 := req1.CopyReq()
	require.Equal(t, req1.RuleID, req2.RuleID)
}

func TestRequest_Sign(t *testing.T) {
	req, signer := createRequest()
	sig, err := signer.Sign(req)
	if err != nil {
		log.ErrFatal(err)
	}
}

func TestRequest_Verify(t *testing.T) {
	req, signer := createRequest()
	sig, err := signer.Sign(req)
	if err != nil {
		log.ErrFatal(err)
	}
}

func TestDarc_IncrementVersion(t *testing.T) {
	d := createDarc().darc
	previousVersion := d.Version
	d.IncrementVersion()
	require.NotEqual(t, previousVersion, d.Version)
}

/*
func Test_EvaluateExpression() {	
} 

func TestSigner(t *testing.T) {
}

func TestRule(t *testing.T) {
}

func TestSubject(t *testing.T) {
}
*/

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
	td.rules = append(td, rule)
	td.darc = NewDarc(&td.rules)
	return td
}

func createAdminRule() *testRule {
	tr := &testRule{}
	action := "Admin"
	expression := `{"and" : [0, 1]}`
	for i := 0; i < 3; i++ {
		s := createSubject_PK()
		tr.subjects = append(tr, s)
	}
	tr.rule = NewRule(action, &tr.subjects, expression)
	return tr
}

func createRule() *testRule {
	tr := &testRule{}
	action := "Read"
	expression := `{}`
	s1 := createSubject_PK()
	s2 := createSubject_Darc()
	tr.subjects = append(tr, s1)
	tr.subjects = append(tr, s2)
	tr.rule = NewRule(action, &tr.subjects, expression)
	return tr
}

func createSubject_Darc() *Subject {
	rule := createAdminRule().rule
	var rules *[]*Rule
	rules = append(rules, rule)
	darc := NewDarc(rules)
	id := darc.GetID()
	subjectdarc := NewSubjectDarc(id)
	subject, err := NewSubject(subjectdarc, nil)
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
	subjectpk := NewSubjectPK(signer.Point)
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
	request := NewRequest(dr_id, 0, sub)
	tr.request = request
	return tr, sig
}