package scanner

import "testing"

func TestListableBucketRequiresXMLRoot(t *testing.T) {
	valid := [][]byte{
		[]byte(`<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>public</Name></ListBucketResult>`),
		[]byte(`<s3:ListBucketResult xmlns:s3="urn:s3"><s3:Contents><s3:Key>a.txt</s3:Key></s3:Contents></s3:ListBucketResult>`),
	}
	for _, body := range valid {
		if !isListableBucketXML(body) {
			t.Fatalf("real bucket listing rejected: %s", body)
		}
	}

	invalid := [][]byte{
		[]byte(`<rss><channel><Contents>guide</Contents><Key>value</Key></channel></rss>`),
		[]byte(`<urlset><Contents>docs</Contents></urlset>`),
		[]byte(`<response><Key>ordinary-api-key</Key></response>`),
		[]byte(`<html><body>&lt;ListBucketResult&gt; documentation</body></html>`),
		[]byte(`not xml <ListBucketResult>`),
	}
	for _, body := range invalid {
		if isListableBucketXML(body) {
			t.Fatalf("ordinary content confirmed as open bucket: %s", body)
		}
	}
}
