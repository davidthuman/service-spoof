package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"
)

func createKeyValuePairsTop(m map[string]map[string][]string) string {
	b := new(bytes.Buffer)
	for key, value := range m {
		fmt.Fprintf(b, "\n%s=%s", key, createKeyValuePairsBottom(value))
	}
	return b.String()
}

func createKeyValuePairsBottom(m map[string][]string) string {
	b := new(bytes.Buffer)
	for key, value := range m {
		fmt.Fprintf(b, "\n\t%s: %s", key, value)
	}
	return b.String()
}

func compareHTTPResponses(want, actual *http.Response) (bool, string) {
	if want == nil || actual == nil {
		return want == actual, "a response is nil"
	}

	if want.StatusCode != actual.StatusCode {
		return false, fmt.Sprintf(`status codes are not equal, want %d, actual %d`, want.StatusCode, actual.StatusCode)
	}

	if !reflect.DeepEqual(want.Header, actual.Header) {

		mismatch := make(map[string]map[string][]string)

		for k := range want.Header {
			if !reflect.DeepEqual(want.Header[k], actual.Header[k]) {

				mismatchHeader := make(map[string][]string)
				mismatchHeader["want"] = want.Header[k]
				mismatchHeader["actual"] = actual.Header[k]

				mismatch[k] = mismatchHeader
			}
		}
		for k := range actual.Header {
			_, exists := mismatch[k]
			if !exists && !reflect.DeepEqual(want.Header[k], actual.Header[k]) {

				mismatchHeader := make(map[string][]string)
				mismatchHeader["want"] = want.Header[k]
				mismatchHeader["actual"] = actual.Header[k]

				mismatch[k] = mismatchHeader
			}
		}

		return false, fmt.Sprintf("headers are not equal: %s", createKeyValuePairsTop(mismatch))
	}

	bodyWant, err := io.ReadAll(want.Body)
	if err != nil {
		return false, fmt.Sprintf(`error when reading body from want: %v`, err)
	}
	want.Body.Close()
	want.Body = io.NopCloser(bytes.NewBuffer(bodyWant))

	bodyActual, err := io.ReadAll(actual.Body)
	if err != nil {
		return false, fmt.Sprintf(`error when reading body from actual: %v`, err)
	}
	actual.Body.Close()
	actual.Body = io.NopCloser(bytes.NewBuffer(bodyActual))

	if !bytes.Equal(bodyWant, bodyActual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(bodyWant), string(bodyActual), true)
		return false, dmp.DiffPrettyText(diffs)
	}

	return true, ""
}

func TestApache(t *testing.T) {

	respWant, err := http.Get("http://localhost:8080/testing")

	if err != nil {
		t.Fatalf(`error when requesting from apache: %v`, err)
	}

	resp, err := http.Get("http://localhost:8070/testing")

	if err != nil {
		t.Fatalf(`error when requesting from spoof: %v`, err)
	}

	equal, msg := compareHTTPResponses(respWant, resp)

	if !equal {
		t.Fatalf(`responses are not equal: %s`, msg)
	}
}
