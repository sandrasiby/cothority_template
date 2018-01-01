package darc

import (
	"gopkg.in/dedis/crypto.v0/abstract"
)

// ID is the identity of a Darc - which is the sha256 of its protobuf representation
type ID []byte

// Darc is the basic structure representing an access control. 
type Darc struct {
	//Version should be monotonically increasing over the evolution of a Darc.
	Version uint32
	//List of rules for the access control policy
	Rules *[]*Rule
}

type Rule struct {
	//Allowed action.
	Action string
	//List of users who can perform the action.
	Subjects *[]*Subject
	//Expression to express fancy conjunctions.
	//Of the format {"operator" : [indices]}
	//Operators can be AND, OR
	//Indices are the indices of the Subjects array
	//Example {"AND" : [1, 2]} means Subjects[1] AND Subjects[2]
	Expression string
}

//Subject can be either a public key or another Darc.
type Subject struct {
	//Darc Subject
	Darc *SubjectDarc
	//PK Subject
	PK *SubjectPK
}

//SubjectEd25519 holds a Ed25519 public key (Point)
type SubjectPK struct {
	Point abstract.Point
}

//SubjectDarc is a structure that points to a Darc with a given ID on a skipchain
type SubjectDarc struct {
	ID ID
}

//To-do: Request for change to a darc?
type Request struct {
	//ID of the Darc having the access control policy
	DarcID ID
	//ID showing allowed rule
	RuleID uint32
	//Requester's details
	Requester *Subject
}
