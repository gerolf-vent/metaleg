package ipset

import "encoding/xml"

type XMLIPSets struct {
	XMLName xml.Name   `xml:"ipsets"`
	IPSets  []XMLIPSet `xml:"ipset"`
}

type XMLIPSet struct {
	XMLName  xml.Name         `xml:"ipset"`
	Name     string           `xml:"name,attr"`
	Type     string           `xml:"type"`
	Revision int              `xml:"revision"`
	Header   XMLIPSetHeader   `xml:"header"`
	Members  []XMLIPSetMember `xml:"members>member"`
}

type XMLIPSetHeader struct {
	XMLName    xml.Name `xml:"header"`
	Family     string   `xml:"family"`
	Hashsize   int      `xml:"hashsize"`
	MaxElem    int      `xml:"maxelem"`
	Timeout    int      `xml:"timeout,omitempty"`
	BucketSize int      `xml:"bucketsize"`
	InitVal    string   `xml:"initval"`
	Memsize    int      `xml:"memsize"`
	References int      `xml:"references"`
	NumEntries int      `xml:"numentries"`
}

type XMLIPSetMember struct {
	XMLName xml.Name `xml:"member"`
	Elem    string   `xml:"elem"`
	Timeout int      `xml:"timeout,omitempty"`
}
