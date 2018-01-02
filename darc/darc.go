/*
Package darc in most of our projects we need some kind of access control to protect resources. Instead of having a simple password
or public key for authentication, we want to have access control that can be:
evolved with a threshold number of keys
be delegated
So instead of having a fixed list of identities that are allowed to access a resource, the goal is to have an evolving
description of who is allowed or not to access a certain resource.
*/
package darc

import (
	"errors"
	"fmt"

	"bytes"
	"strings"
	"crypto/sha256"
	"encoding/json"

	"github.com/dedis/protobuf"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/crypto.v0/ed25519"
	"gopkg.in/dedis/crypto.v0/sign"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

// NewDarc initialises a darc-structure
func NewDarc(category string, rules *[]*Rule) *Darc {
	var ru []*Rule
	ru = append(ru, *rules...)
	return &Darc{
		Version: 0,
		Rules: &ru
	}
}

//Use as Darc.NewRule
func (d *Darc) NewRule(action string, subjects *[]*Subject, expression string) *Rule {
	var subs []*Subject
	subs = append(sub, *subjects..)
	return &Rule{
		Action: action,
		Subjects: &subs,
		Expression: &expression
	}
}

// NewSubject creates an identity with either a link to another darc
// or an Ed25519 identity (containing a point). You're only allowed
// to give either a darc or a point, but not both.
func NewSubject(darc *SubjectDarc, pk *SubjectPK) (*Subject, error) {
	if darc != nil && pk != nil {
		return nil, errors.New("cannot have both darc and ed25519 point in one subject")
	}
	if darc == nil && pk == nil {
		return nil, errors.New("give one of darc or point")
	}
	return &Subject{
		Darc: darc,
		PK: pk,
	}, nil
}

// NewSubjectDarc creates a new darc identity struct given a darcid
func NewSubjectDarc(id ID) *SubjectDarc {
	return &SubjectDarc{
		ID: id,
	}
}

// NewSubjectPK creates a new ed25519 identity given a public-key point
func NewSubjectPK(point abstract.Point) *SubjectPK {
	return &SubjectPK{
		Point: point,
	}
}

// Copy all the fields of a Darc
func (d *Darc) Copy() *Darc {
	dCopy := &Darc{
		Version: d.Version
	}
	if d.Rules != nil {
		rules := append([]*Rule{}, *d.Rules)
		dCopy.Rules = &rules
	}
	return dCopy
}

// ToProto returns a protobuf representation of the Darc-structure.
// We copy a darc first to keep only invariant fields which exclude
// the delegation signature.
func (d *Darc) ToProto() ([]byte, error) {
	dc := d.Copy()
	b, err := protobuf.Encode(dc)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// NewDarcFromProto interprets a protobuf-representation of the darc and
// returns a created Darc.
func NewDarcFromProto(protoDarc []byte) *Darc {
	d := &Darc{}
	protobuf.Decode(protoDarc, d)
	return d
}

// GetID returns the hash of the protobuf-representation of the Darc as its Id.
func (d *Darc) GetID() ID {
	// get protobuf representation
	protoDarc, err := d.ToProto()
	if err != nil {
		log.Error("couldn't convert darc to protobuf for computing its id: " + err.Error())
		return nil
	}
	// compute the hash
	h := sha256.New()
	if _, err := h.Write(protoDarc); err != nil {
		log.Error(err)
		return nil
	}
	hash := h.Sum(nil)
	return ID(hash)
}

//To-do: Add admin rule first?
//Use as 'Darc.AddRule(rule)'
func (d *Darc) AddRule(rule *Rule) ([]*Rules, error) {
	//Check if Admin Rule is trying to be duplicated
	if strings.Compare(rule.Action, "Admin") == 0 {
		for i, r := range *d.Rules {
			if strings.Compare(r.Action, "Admin") {
				return nil, errors.New("Cannot have two Admin rules")
			}
		}
	}
	var rules []*Rule
	if d.Rules != nil {
		rules = *d.Rules
	}
	rules = append(rules, rule)
	d.Rules = &rules
	return *d.Rules, nil
}

//Use as 'Darc.RemoveRule(rule)'
func (d *Darc) RemoveRule(ruleind uint32) ([]*Rules, error) {
	var ruleIndex = -1
	var rules []*Rule
	if d.Rules == nil {
		return nil, errors.New("Empty rule list")
	}
	rules = *d.Rules
	for i, r := range *d.Rules {
		if i == ruleind {
			if strings.Compare(r.Action, "Admin") {
				return nil, errors.New("Cannot remove Admin rule")
			}
			ruleIndex = i
		}
	}
	if ruleIndex == -1 {
		return nil, errors.New("Rule is not present in the Darc")
	}
	//Removing rule
	rules = append(rules[:ruleIndex], rules[ruleIndex+1:]...)
	d.Rules = &rules
	return *d.Rules, nil
}

func (d *Darc) RuleUpdateAction(ruleind uint32, action string) ([]*Rules, error) {
	var ruleIndex = -1
	rules = *d.Rules
	if d.Rules == nil {
		return nil, errors.New("Empty rule list")
	}
	for i, r := range *d.Rules {
		if i == ruleind {
			ruleIndex = i
		}
	}
	if ruleIndex == -1 {
		return nil, errors.New("Rule ID not found")
	}
	rules[ruleIndex].Action = action
	d.Rules = &rules
	return *d.Rules, nil
}

func (d *Darc) RuleAddSubject(ruleind uint32, subject *Subject) ([]*Rules, error) {
	var ruleIndex = -1
	rules = *d.Rules
	if d.Rules == nil {
		return nil, errors.New("Empty rule list")
	}
	for i, r := range *d.Rules {
		if i == ruleind {
			ruleIndex = i
		}
	}
	if ruleIndex == -1 {
		return nil, errors.New("Rule ID not found")
	}
	var subjects = *rules[ruleIndex].Subjects
	subjects = append(subjects, subject)
	rules[ruleIndex].Subjects = &subjects
	d.Rules = &rules
	return *d.Rules, nil
}

func (d *Darc) RuleRemoveSubject(ruleind uint32, subject *Subject) ([]*Rules, error) {
	var ruleIndex = -1
	rules = *d.Rules
	if d.Rules == nil {
		return nil, errors.New("Empty rule list")
	}
	for i, r := range *d.Rules {
		if i == ruleID {
			ruleIndex = i
		}
	}
	if ruleIndex == -1 {
		return nil, errors.New("Rule ID not found")
	}
	var subjectIndex = -1
	var subjects = *rules[ruleIndex].Subjects
	if subjects == nil {
		return nil, errors.New("Empty subjects list")
	}
	for i, s := range subjects {
		if s == subject {
			subjectIndex = i
		}
	}
	if subjectIndex == -1 {
		return nil, errors.New("Subject ID not found")
	}

	subjects = append(subjects[:subjectIndex], subjects[subjectIndex+1:]...)
	rules[ruleIndex].Subjects = &subjects
	d.Rules = &rules
	return *d.Rules, nil
}

func (d *Darc) RuleUpdateExpression(ruleind uint32, expression string) ([]*Rules, error) {
	var ruleIndex = -1
	rules = *d.Rules
	if d.Rules == nil {
		return nil, errors.New("Empty rule list")
	}
	for i, r := range *d.Rules {
		if i == ruleind {
			ruleIndex = i
		}
	}
	if ruleIndex == -1 {
		return nil, errors.New("Rule ID not found")
	}
	rules[ruleIndex].Expression = expression
	d.Rules = &rules
	return *d.Rules, nil
}

func EvaluateExpression(expression string) {
	in := []byte(expression)
	var raw interface{}
	json.Unmarshal(in, &raw)
	ProcessJson(raw)
}

var s string

//For now, we just take a JSON expression and convert it into 
// a string showing evaluation. This will be replaced by actual
//evaluation when we introduce signatures
func ProcessJson(raw interface{}) {
	m := raw.(map[string]interface{})
	for k, v := range(m) {
		switch vv := v.(type) {
			case []interface{}:
				for i, u := range vv {
					switch x := u.(type) {
						case map[string]interface {}:
							test(x)
						case string: 
						 	if i == 0 {
								s += "(" + x
							} else {
								s += " " + k + " " + x
							} 
							if i == len(vv) - 1 {
								s += ")"
							}							
							fmt.Println(s)
						default:
							fmt.Println("Strange")
					}
				}
			default:
				fmt.Println("Why does it land here?")
		}
	}
}

func (r *Request) CopyReq() *Request {
	rCopy := &Request{
		DarcID: r.DarcID,
		RuleID: r.RuleID,
		Requester: r.Requester
	}
	return rCopy
}

func (s *Signer) Sign(req *Request) ([]byte, error) {
	rc := req.CopyReq()
	b, err := protobuf.Encode(rc)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, errors.New("nothing to sign, message is empty")
	}
	if s.Ed25519 != nil {
		key, err := s.GetPrivate()
		if err != nil {
			return nil, errors.New("could not retrieve a private key")
		}
		return sign.Schnorr(ed25519.NewAES128SHA256Ed25519(false), key, b)
	}
	return nil, errors.New("signer is of unknown type")
}

func (s *Signer) GetPrivate() (abstract.Scalar, error) {
	if s.Ed25519 != nil {
		if s.Ed25519.Secret != nil {
			return s.Ed25519.Secret, nil
		}
		return nil, errors.New("signer lacks a private key")
	}
	return nil, errors.New("signer is of unknown type")
}

func Verify(req *Request, sig []byte, darcs *[]*Darc) error {
	//Check if signature is correct
	if sig == nil || len(sig) == 0 {
		return errors.New("No signature available")
	}
	//Get path from rule to requester, check if it is correct
	verpath, err := VerifyPath(darcs, req)
	if err != nil {
		return err
	}
	//Check expression
}

func VerifyPath(darcs *[]*Darc, req *Request) error {
	//Find Darc from request DarcID
	targetDarc, err := FindDarc(darcs, req.DarcID)
	if err != nil {
		return err
	}
	rules := targetDarc.Rules
	targetRule, err := FindRule(rules, req.RuleID)
	if err != nil {
		return err
	}
	requester := req.Requester 
	sub, err = targetRule.Subjects
	if err != nil {
		return err
	}
	return nil
}

func FindSubject(subjects *[]*Subject, requester) error {
	for i, s := range subjects {
		if s == requester {
			return nil
		} else if s.SubjectDarc {
			targetDarc, err := FindDarc(darcs, req.DarcID)
			if err != nil {
				return err
			}
			subs = targetDarc.Rules[0].Subjects
			sub, err := FindSubject(subs, requester)
			if err != nil {
				return err
			}
		}
	}
	return errors.New("Subject not found")
}

func FindDarc(darcs *[]*Darc, darcid) (*Darc, error) {
	var darcIndex = -1
	for i, d := range darcs {
		if d.GetID() == darcid {
			darcIndex = i
			return d, nil
		}
	}
	if darcIndex == -1 {
		return nil, errors.New("Invalid DarcID")
	}
}

func FindRule(rules *[]*Rules, ruleid) (*Rules, error) {
	if (ruleid > rules.length-1) || (ruleid < 0) {
		return nil, errors.New("Invalid RuleID in request")
	}
	return rules[ruleid], nil
} 

// NewEd25519Signer initializes a new Ed25519Signer given a public and private keys.
// If any of the given values is nil or both are nil, then a new key pair is generated.
func NewEd25519Signer(point abstract.Point, secret abstract.Scalar) *Ed25519Signer {
	if point == nil || secret == nil {
		kp := config.NewKeyPair(network.Suite)
		point, secret = kp.Public, kp.Secret
	}
	return &Ed25519Signer{
		Point:  point,
		Secret: secret,
	}
}

// IncrementVersion updates the version number of the Darc
func (d *Darc) IncrementVersion() {
	d.Version++
}

// IsNull returns true if this DarcID is not initialised.
func (di ID) IsNull() bool {
	return di == nil
}

// Equal compares with another DarcID.
func (di ID) Equal(other ID) bool {
	return bytes.Equal([]byte(di), []byte(other))
}