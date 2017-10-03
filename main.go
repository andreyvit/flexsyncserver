package main

import (
	"bytes"
	// "crypto/sha1"
	"crypto/md5"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
)

const (
	missingObjectHash = "00000000000000000000000000000000"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ltime)

	var port int
	var srv Server
	flag.IntVar(&port, "port", 3003, "TCP port to listen on")
	flag.StringVar(&srv.rootDir, "db", "/tmp/flexsyncserver", "Database root folder")
	flag.Parse()

	http.HandleFunc("/o/", srv.HandleObject)

	log.Printf("Sync server running on port %d with database at %s", port, srv.rootDir)
	err := http.ListenAndServe(net.JoinHostPort("", strconv.Itoa(port)), nil)
	if err != nil {
		panic(err)
	}
}

type Server struct {
	rootDir string
	mut     sync.Mutex
}

func (srv *Server) Resolve(fn string) string {
	return path.Join(srv.rootDir, fn)
}

func (srv *Server) ResolveVersion(fn string, ver int) string {
	ext := path.Ext(fn)
	base := fn[:len(fn)-len(ext)]

	return path.Join(srv.rootDir, "_versions", fmt.Sprintf("%s.v%05d%s", base, ver, ext))
}

func (srv *Server) handleEnumerate(w http.ResponseWriter, r *http.Request) error {
	glob := r.FormValue("glob")
	if glob == "" {
		glob = "*"
	}
	return srv.handleEnumerateGlob(w, r, r.URL.Path, glob)
}

func (srv *Server) handleEnumerateGlob(w http.ResponseWriter, r *http.Request, dirname, glob string) error {
	var buf bytes.Buffer

	var includeHash, includeBody bool
	includeKey := true
	value := r.FormValue("v")
	if value == "hash" {
		includeHash = true
	} else if value == "body" {
		includeBody = true
	} else if value == "hash,body" {
		includeHash = true
		includeBody = true
	} else if value == "none" || value == "" {
		// nop
	} else {
		return &StatusError{http.StatusBadRequest, "invalid 'value' param", nil, value}
	}
	key := r.FormValue("k")
	includeKey = (key != "none")
	isMap := includeKey && (includeHash || includeBody)

	dirname = srv.Resolve(dirname)

	srv.mut.Lock()
	defer srv.mut.Unlock()

	files, err := ioutil.ReadDir(dirname)
	if err != nil && !os.IsNotExist(err) {
		return &StatusError{http.StatusInternalServerError, "internal I/O error", err, "ReadDir failed"}
	}

	if isMap {
		buf.WriteString("{")
	} else {
		buf.WriteString("[")
	}
	count := 0
	for _, file := range files {
		name := file.Name()
		if file.IsDir() && includeBody {
			continue
		}

		matched, err := path.Match(glob, name)
		if err != nil {
			return &StatusError{http.StatusBadRequest, "invalid glob", err, glob}
		}
		if !matched {
			continue
		}

		if count > 0 {
			buf.WriteString(",\n")
		} else {
			buf.WriteString("\n")
		}
		count++

		buf.WriteString("  ")
		if includeKey {
			buf.WriteString("  \"")
			buf.WriteString(name)
			buf.WriteString("\"")
		}

		if includeHash || includeBody {
			if includeKey {
				buf.WriteString(": ")
			}
			data, err := ioutil.ReadFile(path.Join(dirname, name))
			if err != nil {
				return &StatusError{http.StatusInternalServerError, "internal I/O error", err, "ReadFile failed"}
			}

			if includeHash && includeHash {
				buf.WriteString("[")
			}
			if includeHash {
				buf.WriteString("\"")
				buf.WriteString(Hash(data))
				buf.WriteString("\"")
			}
			if includeHash && includeHash {
				buf.WriteString(",")
			}
			if includeBody {
				data = bytes.Replace(data, []byte("\n"), []byte("\n  "), -1)
				buf.Write(data)
			}
			if includeHash && includeHash {
				buf.WriteString("]")
			}
		}
	}
	if isMap {
		buf.WriteString("\n}")
	} else {
		buf.WriteString("\n]")
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(buf.Bytes())
	return nil
}

func (srv *Server) handleRead(w http.ResponseWriter, r *http.Request) error {
	base := path.Base(r.URL.Path)
	if strings.ContainsAny(base, "*?[") {
		return srv.handleEnumerateGlob(w, r, path.Dir(r.URL.Path), base)
	}

	fn := srv.Resolve(r.URL.Path)

	srv.mut.Lock()
	defer srv.mut.Unlock()

	data, err := ioutil.ReadFile(fn)
	if err != nil {
		if os.IsNotExist(err) {
			return &StatusError{http.StatusNotFound, "not found", err, ""}
		} else {
			return &StatusError{http.StatusInternalServerError, "internal I/O error", err, "ReadFile failed"}
		}
	}

	hash := Hash(data)
	w.Header().Set("ETag", FormatETag(hash))
	_, _ = w.Write(data)

	return nil
}

func (srv *Server) handleWrite(w http.ResponseWriter, r *http.Request) error {
	if strings.HasSuffix(r.URL.Path, "/") {
		return &StatusError{http.StatusBadRequest, "cannot write to a folder", nil, r.URL.Path}
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return &StatusError{http.StatusInternalServerError, "internal networking error", err, "RealAll(body) failed"}
	}

	fn := srv.Resolve(r.URL.Path)
	err = os.MkdirAll(path.Dir(fn), 0755)
	if err != nil {
		return &StatusError{http.StatusInternalServerError, "internal I/O error", err, "MkdirAll failed"}
	}

	hash := Hash(body)

	srv.mut.Lock()
	defer srv.mut.Unlock()

	condHash, ok := ParseETag(r.Header.Get("If-Match"))
	if !ok {
		return &StatusError{http.StatusBadRequest, "invalid If-Match format", nil, r.Header.Get("If-Match")}
	}

	if condHash != "" {
		var oldHash string

		old, err := ioutil.ReadFile(fn)
		if err != nil {
			if os.IsNotExist(err) {
				oldHash = missingObjectHash
				// return &StatusError{http.StatusNotFound, "not found", err, ""}
			} else {
				return &StatusError{http.StatusInternalServerError, "internal I/O error", err, "ReadFile failed"}
			}
		} else {
			oldHash = Hash(old)
		}

		if condHash != oldHash {
			// log.Printf("%s: conflict: requested %q != actual %q", fn, condHash, oldHash)
			http.Error(w, fmt.Sprintf("conflict %v %v", oldHash, condHash), http.StatusPreconditionFailed)
			return nil
		}
	}

	err = ioutil.WriteFile(fn, body, 0644)
	if err != nil {
		return &StatusError{http.StatusInternalServerError, "internal I/O error", err, "WriteFile failed"}
	}

	if true {
		for ver := 1; ; ver++ {
			fn = srv.ResolveVersion(r.URL.Path, ver)
			err = os.MkdirAll(path.Dir(fn), 0755)
			if err != nil {
				return &StatusError{http.StatusInternalServerError, "internal I/O error", err, "MkdirAll failed (writing version)"}
			}

			if _, err := os.Stat(fn); err == nil {
				continue
			}

			err = ioutil.WriteFile(fn, body, 0644)
			if err != nil {
				return &StatusError{http.StatusInternalServerError, "internal I/O error", err, "WriteFile failed (writing version)"}
			}
			break
		}
	}

	http.Error(w, hash, http.StatusOK)
	return nil
}

func (srv *Server) HandleObject(w http.ResponseWriter, r *http.Request) {
	var err error

	prefix := "/o/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		panic("invalid URL routed to HandleObject")
	}
	r.URL.Path = r.URL.Path[len(prefix)-1:]

	r.URL.Path = path.Clean(r.URL.Path)
	if strings.Contains(r.URL.Path, "..") {
		err = errors.New("insecure path")
	} else if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if strings.HasSuffix(r.URL.Path, "/") {
			err = srv.handleEnumerate(w, r)
		} else {
			err = srv.handleRead(w, r)
		}
	} else if r.Method == http.MethodPut || r.Method == http.MethodPost {
		err = srv.handleWrite(w, r)
	}

	if err != nil {
		se, _ := err.(*StatusError)
		if se == nil {
			se = &StatusError{http.StatusInternalServerError, "internal error", err, ""}
		}
		log.Printf("** %s %s: %s (%v, %s)", r.Method, r.URL.Path, se.PublicMessage, se.Underlying, se.DebugMessage)
		http.Error(w, se.PublicMessage, se.Status)
	} else {
		log.Printf("%s %s", r.Method, r.URL.Path)
	}
}

type StatusError struct {
	Status        int
	PublicMessage string
	Underlying    error
	DebugMessage  string
}

func (e *StatusError) Error() string {
	return e.PublicMessage
}

func Hash(data []byte) string {
	// raw := sha256.Sum256(data)
	// raw := sha1.Sum(data)
	raw := md5.Sum(data)
	return fmt.Sprintf("%x", raw)
}

func FormatETag(hash string) string {
	return "\"" + hash + "\""
}

func ParseETag(etag string) (string, bool) {
	etag = strings.TrimSpace(etag)
	if etag == "" {
		return "", true
	}
	if strings.HasPrefix(etag, "\"") && strings.HasSuffix(etag, "\"") {
		etag = etag[1 : len(etag)-1]
		if strings.IndexFunc(etag, isBadHashChar) == -1 {
			return strings.ToLower(etag), true
		}
	}
	return "", false
}

func isBadHashChar(r rune) bool {
	return !((r >= 'A' && r <= 'F') || (r >= 'a' && r <= 'f') || (r >= '0' && r <= '9'))
}
