package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/barelyhuman/auditor/internal/lockfile"
)

const (
	baseURL    = "https://api.osv.dev/v1"
	batchSize  = 500
	maxWorkers = 10
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// QueryPackages queries OSV for all packages and returns a map of packageName → vulns.
func QueryPackages(packages []lockfile.Package) (map[string][]Vulnerability, error) {
	// Step 1: batch query for vuln IDs
	vulnIDs, pkgVulnMap, err := batchQuery(packages)
	if err != nil {
		return nil, err
	}
	if len(vulnIDs) == 0 {
		return map[string][]Vulnerability{}, nil
	}

	// Step 2: fetch full details for unique IDs
	details, err := fetchVulnDetails(vulnIDs)
	if err != nil {
		return nil, err
	}

	// Step 3: build result map keyed by package name
	result := make(map[string][]Vulnerability)
	for pkgKey, ids := range pkgVulnMap {
		for _, id := range ids {
			if v, ok := details[id]; ok {
				result[pkgKey] = append(result[pkgKey], v)
			}
		}
	}
	return result, nil
}

// batchQuery sends packages in chunks and collects unique vuln IDs.
// Returns: unique vuln IDs set, map of "name|version" → []vulnID, error
func batchQuery(packages []lockfile.Package) (map[string]struct{}, map[string][]string, error) {
	uniqueIDs := make(map[string]struct{})
	pkgVulnMap := make(map[string][]string)

	for start := 0; start < len(packages); start += batchSize {
		end := start + batchSize
		if end > len(packages) {
			end = len(packages)
		}
		chunk := packages[start:end]

		req := BatchRequest{Queries: make([]Query, len(chunk))}
		for i, p := range chunk {
			req.Queries[i] = Query{
				Version: p.Version,
				Package: PkgRef{Name: p.Name, Ecosystem: "npm"},
			}
		}

		resp, err := postJSON(baseURL+"/querybatch", req)
		if err != nil {
			return nil, nil, fmt.Errorf("OSV querybatch: %w", err)
		}

		var batchResp BatchResponse
		if err := json.Unmarshal(resp, &batchResp); err != nil {
			return nil, nil, fmt.Errorf("parse OSV response: %w", err)
		}

		for i, result := range batchResp.Results {
			if i >= len(chunk) {
				break
			}
			pkg := chunk[i]
			key := pkg.Name + "|" + pkg.Version
			for _, v := range result.Vulns {
				uniqueIDs[v.ID] = struct{}{}
				pkgVulnMap[key] = append(pkgVulnMap[key], v.ID)
			}
		}
	}
	return uniqueIDs, pkgVulnMap, nil
}

// fetchVulnDetails fetches full details for each unique vuln ID concurrently.
func fetchVulnDetails(ids map[string]struct{}) (map[string]Vulnerability, error) {
	type result struct {
		id   string
		vuln Vulnerability
		err  error
	}

	idList := make([]string, 0, len(ids))
	for id := range ids {
		idList = append(idList, id)
	}

	sem := make(chan struct{}, maxWorkers)
	results := make(chan result, len(idList))
	var wg sync.WaitGroup

	for _, id := range idList {
		wg.Add(1)
		go func(vulnID string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			data, err := getJSON(fmt.Sprintf("%s/vulns/%s", baseURL, vulnID))
			if err != nil {
				results <- result{id: vulnID, err: err}
				return
			}
			var v Vulnerability
			if err := json.Unmarshal(data, &v); err != nil {
				results <- result{id: vulnID, err: err}
				return
			}
			results <- result{id: vulnID, vuln: v}
		}(id)
	}

	wg.Wait()
	close(results)

	details := make(map[string]Vulnerability, len(idList))
	for r := range results {
		if r.err != nil {
			return nil, fmt.Errorf("fetch vuln %s: %w", r.id, r.err)
		}
		details[r.id] = r.vuln
	}
	return details, nil
}

func postJSON(url string, body any) ([]byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	return io.ReadAll(resp.Body)
}

func getJSON(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	return io.ReadAll(resp.Body)
}
