// Command genoui builds the embedded MAC-address-to-manufacturer table.
//
// It downloads the three IEEE registries that together cover every assigned
// prefix, strips them down to "prefix<TAB>vendor" lines and writes a gzipped
// file that the server embeds. Run it from the repository root:
//
//	go run ./tools/genoui
//
// The IEEE files total roughly 6 MB; the generated table is around 400 KB.
package main

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Each registry allocates a different number of leading bits: MA-L is the
// classic 24-bit OUI, MA-M is 28 bits and MA-S is 36 bits.
var sources = []struct {
	name string
	url  string
}{
	{"MA-L", "https://standards-oui.ieee.org/oui/oui.csv"},
	{"MA-M", "https://standards-oui.ieee.org/oui28/mam.csv"},
	{"MA-S", "https://standards-oui.ieee.org/oui36/oui36.csv"},
}

func main() {
	entries := map[string]string{}

	for _, src := range sources {
		count, err := fetch(src.url, entries)
		if err != nil {
			log.Printf("WARNING: could not fetch %s (%s): %v", src.name, src.url, err)
			continue
		}
		log.Printf("%s: %d assignments", src.name, count)
	}

	if len(entries) == 0 {
		log.Fatal("no data downloaded; refusing to overwrite the existing table")
	}

	prefixes := make([]string, 0, len(entries))
	for prefix := range entries {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)

	outPath := filepath.Join("data", "oui.gz")
	if err := os.MkdirAll("data", 0o755); err != nil {
		log.Fatalf("could not create data directory: %v", err)
	}
	file, err := os.Create(outPath)
	if err != nil {
		log.Fatalf("could not create %s: %v", outPath, err)
	}
	defer file.Close()

	writer, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		log.Fatalf("could not compress: %v", err)
	}
	for _, prefix := range prefixes {
		if _, err := fmt.Fprintf(writer, "%s\t%s\n", prefix, entries[prefix]); err != nil {
			log.Fatalf("could not write: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		log.Fatalf("could not finish compressing: %v", err)
	}

	info, _ := file.Stat()
	log.Printf("wrote %s: %d prefixes, %.0f KB", outPath, len(entries), float64(info.Size())/1024)
}

func fetch(url string, into map[string]string) (int, error) {
	client := &http.Client{Timeout: 3 * time.Minute}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	// The IEEE server answers "418 I'm a teapot" to clients that do not send a
	// browser-like User-Agent.
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; WoL-go OUI updater)")
	req.Header.Set("Accept", "text/csv,text/plain,*/*")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	reader := csv.NewReader(resp.Body)
	reader.FieldsPerRecord = -1

	var count int
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}
		// Columns: Registry, Assignment, Organization Name, Organization Address
		if len(record) < 3 || strings.EqualFold(record[0], "Registry") {
			continue
		}
		prefix := strings.ToUpper(strings.TrimSpace(record[1]))
		vendor := shorten(record[2])
		if prefix == "" || vendor == "" {
			continue
		}
		into[prefix] = vendor
		count++
	}
	return count, nil
}

// shorten trims the legal boilerplate off company names so they fit in the
// small chips the web interface draws them in.
func shorten(name string) string {
	name = strings.TrimSpace(name)
	name = strings.Join(strings.Fields(name), " ")

	// Drop everything after a comma, which is almost always a legal suffix
	// such as ", Inc." or ", Co., Ltd.".
	if idx := strings.Index(name, ","); idx > 0 {
		name = name[:idx]
	}

	suffixes := []string{
		" Corporation", " Corp.", " Corp", " Incorporated", " Inc.", " Inc",
		" Limited", " Ltd.", " Ltd", " LLC", " L.L.C.", " GmbH", " AG", " S.A.",
		" B.V.", " N.V.", " Co.", " Company", " PLC", " Pty", " A/S", " AB", " Oy",
		" S.p.A.", " SAS", " SARL", " KG", " Group", " Technologies", " Technology",
	}
	// Registrants are inconsistent about case ("Co." vs "CO."), so match the
	// suffixes case-insensitively.
	for changed := true; changed; {
		changed = false
		lower := strings.ToLower(name)
		for _, suffix := range suffixes {
			if len(name) > len(suffix)+2 && strings.HasSuffix(lower, strings.ToLower(suffix)) {
				name = strings.TrimSpace(name[:len(name)-len(suffix)])
				changed = true
				break
			}
		}
	}

	if len([]rune(name)) > 40 {
		name = string([]rune(name)[:40])
	}
	return strings.TrimSpace(name)
}
