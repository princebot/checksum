// checksum is a utility for verifying checksums on all files in a directory.
package main

// TODO(princebot): Add a flag for recursing through directories.

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"text/template"

	"github.com/Sirupsen/logrus"

	"bitbucket.org/princebot/debugger"
	"github.com/fatih/color"
	"github.com/mattn/go-colorable"
)

const (
	Prog   = "checksum"
	Source = "checksum.go"
)

// Note the format specifier directly below ”option”: This is where printHelp
// inserts the options-usage section.
const usage = `
  {{b "name:"}}

	{{b .prog}} - verify checksums for all files in a directory

  {{b "options:"}}

%s
  {{b "usage:"}}

      	For each file in the given directory, {{b .prog}} looks for a matching
        checksum file <{{u "basename"}}>.<{{u "hash-type"}}>.

        {{u "hash-type"}} can be any of these supported hash algorithms:

                - md5
                - sha1
                - sha224
                - sha256

        The checksum file should contain only a hash for another file, e.g.,

                foo.tar.gz      (file to check)
                foo.tar.gz.md5  (MD5 checksum for foo.tar.gz)

                bar.zip         (file to check)
                bar.zip.sha256  (SHA-256 checksum for bar.zip)

        The source for {{b .prog}} lives in a single file, so you can bundle it
        with a directory of files for transfer and use it at the destination
        to perform checksums. Because it defaults to the current directory
        when run without arguments, you can do things like this:

                1. Compress a directory of large files with {{u "checksum.go"}}
                   placed at the root.
                2. Transfer the files.
                3. Unpack the files.
                4. Run {{b "go run checksum.go"}}

  {{b "online docs:"}}

	« {{c "https://github.com/princebot/checksum"}} »
	« {{c "https://godoc.org/github.com/princebot/checksum"}} »
`

var (
	flagset = flag.NewFlagSet(Prog, flag.ContinueOnError)
	help    = flagset.Bool("help", false, "display this help and quit")
	dirpath = flagset.String(
		"path", "", "directory path (default: current directory)",
	)

	stderr = colorable.NewColorableStderr()
	red    = color.New(color.FgRed).SprintfFunc()
	log    = logrus.New()
)

func init() {
	flagset.SetOutput(ioutil.Discard)
	log.Level = logrus.DebugLevel
	log.Formatter = &logrus.TextFormatter{FullTimestamp: true}
	log.Out = stderr
}

type Filelist map[string]*FilePair

func (l Filelist) CheckAll() (<-chan *ChecksumInfo, <-chan error) {
	var (
		lim  = make(chan struct{}, 5)
		rc   = make(chan *ChecksumInfo, len(l))
		errc = make(chan error, 1)
		wg   sync.WaitGroup
	)
	go func() {
		defer close(rc)
		defer close(errc)
		for _, p := range l {
			lim <- struct{}{}
			wg.Add(1)
			go func(p *FilePair) {
				defer wg.Done()
				switch r, err := p.Sum(); {
				case err != nil:
					errc <- err
				case !r.OK:
					errc <- r
				default:
					rc <- r
				}
				<-lim
			}(p)
		}
		wg.Wait()
	}()
	return rc, errc
}

func NewFilelist(dir string) (Filelist, error) {
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()

	ns, err := d.Readdirnames(0)
	if err != nil {
		return nil, err
	}

	var fs []*File
	for _, n := range ns {
		if n == Source {
			continue
		}
		f, err := NewFile(filepath.Join(dir, n))
		if err != nil {
			if err == ErrFileType {
				continue
			}
			return nil, err
		}
		fs = append(fs, f)
	}

	l := make(Filelist)
	for _, f := range fs {
		if f.HashType == "" {
			l[f.key] = &FilePair{f, nil}
			continue
		}
		if p, ok := l[f.key]; ok {
			p.Checksum = f
			continue
		}
		return nil, fmt.Errorf(
			"cannot find original file %v for checksum file %v",
			f.key, f.Base,
		)
	}

	for _, p := range l {
		debugger.Print(p)
	}

	for _, p := range l {
		if p.Checksum == nil {
			return nil, fmt.Errorf(
				"no checksum file found for %v", p.Origin.Base,
			)
		}
	}

	return l, nil
}

var ErrFileType = fmt.Errorf("file is a directory")

type File struct {
	Path     string
	Base     string
	HashType string

	key string
}

func NewFile(path string) (*File, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	} else if fi.IsDir() {
		return nil, ErrFileType
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	base := fi.Name()
	kind := strings.TrimPrefix(filepath.Ext(path), ".")
	if kind == base || kind == "."+base {
		kind = ""
	}

	f := &File{Path: abs, Base: base}
	if KnownHashes[kind] {
		f.HashType = kind
		f.key = strings.TrimSuffix(f.Base, "."+kind)
		debugger.Print(f)
		return f, nil
	}
	f.key = f.Base
	debugger.Print(f)
	return f, nil
}

type FilePair struct {
	Origin   *File
	Checksum *File
}

func (p *FilePair) Sum() (*ChecksumInfo, error) {
	if p.Origin == nil {
		return nil, fmt.Errorf("no file to check")
	}
	if p.Checksum == nil || p.Checksum.HashType == "" {
		return nil, fmt.Errorf("no checksum for %v", p.Origin.Base)
	}

	b, err := ioutil.ReadFile(p.Checksum.Path)
	if err != nil {
		return nil, err
	}
	verifiedChecksum := strings.TrimSpace(string(b))

	kind := p.Checksum.HashType
	if !KnownHashes[kind] {
		return nil, fmt.Errorf("unknown hash algorithm %v", kind)
	}

	path := p.Origin.Path
	checksum, err := KnownHashes.GetChecksum(kind, path)
	if err != nil {
		return nil, err
	}

	return &ChecksumInfo{
		Path:   path,
		Got:    checksum,
		Wanted: verifiedChecksum,
		OK:     checksum == verifiedChecksum,
	}, nil
}

var KnownHashes = HashFactory{
	"md5":    true,
	"sha1":   true,
	"sha224": true,
	"sha256": true,
}

type HashFactory map[string]bool

func (hf HashFactory) GetChecksum(kind string, path string) (string, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	var checksum []byte
	switch kind {
	case "md5":
		a := md5.Sum(b)
		checksum = a[:]
	case "sha1":
		a := sha1.Sum(b)
		checksum = a[:]
	case "sha224":
		a := sha256.Sum224(b)
		checksum = a[:]
	case "sha256":
		a := sha256.Sum256(b)
		checksum = a[:]
	}

	if checksum == nil {
		return "", fmt.Errorf("unknown hash algorithm `%v`", kind)
	}
	return fmt.Sprintf("%x", checksum), nil
}

type ChecksumInfo struct {
	Path   string
	Got    string
	Wanted string
	OK     bool
}

func (i *ChecksumInfo) Error() string {
	var bold, brazen, normal func(...interface{}) string
	var status string

	if i.OK {
		bold = color.New(color.Bold).SprintFunc()
		brazen = color.New(color.FgGreen, color.Bold).SprintFunc()
		normal = fmt.Sprint
		status = "status:    \tchecksum passed"
	} else {
		bold = color.New(color.FgRed, color.Bold).SprintFunc()
		brazen = bold
		normal = color.New(color.FgRed).SprintFunc()
		status = "status:    \tCHECKSUM FAILED"
	}

	return fmt.Sprintf(
		"  %v    \t%v\n  %v    \t%v\n  %v    \t%v\n  %v\n\n",
		bold("file:"), normal(i.Path),
		bold("wanted:"), normal(i.Wanted),
		bold("got:"), normal(i.Got),
		brazen(status),
	)
}

// displayHelp formats and prints usage information to stderr.
func displayHelp() {
	// factory returns an fprint function that prints its arguments to
	// stderr using one or more style attributes.
	factory := func(style ...color.Attribute) func(...interface{}) string {
		sprint := color.New(style...).SprintFunc()
		return func(a ...interface{}) string {
			fmt.Fprint(stderr, sprint(a...))
			color.Unset()
			return ""
		}
	}

	var buf bytes.Buffer
	flagset.SetOutput(&buf)
	flagset.PrintDefaults()
	s := fmt.Sprintf("%s\n", fmt.Sprintf(usage, buf.String()))

	// Convert PrintDefaults’ indentation (spaces, tabs, or a mix) to tabs.
	s = regexp.MustCompile(`(?m)^  -`).ReplaceAllLiteralString(s, "\t-")
	s = regexp.MustCompile("(?m)^    \t").ReplaceAllLiteralString(s, "\t\t")

	// Replace option-section header with a bold-formatter hook.
	flagset.VisitAll(func(f *flag.Flag) {
		oldStr := fmt.Sprintf("\t-%v", f.Name)
		newStr := fmt.Sprintf("\t{{b `-%v`}}", f.Name)
		s = strings.Replace(s, oldStr, newStr, -1)
	})

	// ANSI escapes and Go templates don’t play well together. The present
	// hack: map template functions that print styled text to stderr and
	// return an empty string. This effectively bypasses the template’s
	// writer (which strips ANSI escapes) while still using its parser.
	fm := template.FuncMap{
		"b": factory(color.Bold),
		"c": factory(color.FgCyan),
		"u": factory(color.Underline),
	}
	tmpl := template.New("help").Funcs(fm)
	template.Must(tmpl.Parse(s))
	tmplData := map[string]string{"prog": Prog}
	if err := tmpl.Execute(stderr, tmplData); err != nil {
		panic(fmt.Errorf("internal error: template: %v", err))
	}
	color.Unset()
}

func flagfail(err error) {
	fmt.Fprintf(stderr, red("\nerror: %v\n", err))
	fmt.Fprintf(stderr, "\nusage: %s [options]\n", Prog)
	flagset.SetOutput(stderr)
	flagset.PrintDefaults()
	fmt.Println()
	os.Exit(1)
}

func main() {
	if err := flagset.Parse(os.Args[1:]); err != nil {
		if err != flag.ErrHelp {
			flagfail(err)
		}
		*help = true
	}

	if *help == true {
		displayHelp()
		return
	}

	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	files, err := NewFilelist(dir)
	if err != nil {
		log.Fatal(err)
	}

	var (
		rc, errc = files.CheckAll()
		ct       struct{ ok, err int }
		wg       sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for r := range rc {
			fmt.Fprint(color.Output, r)
			ct.ok++
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for err := range errc {
			fmt.Fprint(color.Output, err)
			ct.err++
		}
	}()

	wg.Wait()
	bold := color.New(color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	fmt.Printf(
		"\n  %v: %v ok, %v errors\n\n",
		bold("Summary"), green(ct.ok), red("%v", ct.err),
	)
}
