package scanner

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

// PDFScanner scans for malicious PDF files
type PDFScanner struct {
	BaseScanner
	scanPaths   []string
	maxFileSize int64 // Max file size to scan in bytes
	maxScanSize int64 // Max bytes to read from each file
	concurrent  int   // Max concurrent file scans
}

// pdfPattern represents a suspicious pattern to detect in PDFs
type pdfPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Severity    entity.Severity
	Category    string
	Description string
}

// PDF magic bytes
var pdfMagic = []byte("%PDF-")

// Suspicious patterns to detect in PDF files
var pdfPatterns = []pdfPattern{
	// JavaScript execution (HIGH risk)
	{
		Name:        "JavaScript Action",
		Pattern:     regexp.MustCompile(`/JS\s`),
		Severity:    entity.SeverityHigh,
		Category:    "JavaScript",
		Description: "PDF contains JavaScript action - can execute arbitrary code",
	},
	{
		Name:        "JavaScript Dictionary",
		Pattern:     regexp.MustCompile(`/JavaScript\s`),
		Severity:    entity.SeverityHigh,
		Category:    "JavaScript",
		Description: "PDF contains JavaScript dictionary entry",
	},
	{
		Name:        "JavaScript Type",
		Pattern:     regexp.MustCompile(`/S\s*/JavaScript`),
		Severity:    entity.SeverityHigh,
		Category:    "JavaScript",
		Description: "PDF contains JavaScript action type declaration",
	},
	{
		Name:        "Acrobat JavaScript API",
		Pattern:     regexp.MustCompile(`(?i)app\.(alert|launch|openDoc|mailMsg|response)`),
		Severity:    entity.SeverityHigh,
		Category:    "JavaScript",
		Description: "PDF uses Acrobat JavaScript API functions",
	},
	{
		Name:        "JavaScript eval",
		Pattern:     regexp.MustCompile(`(?i)eval\s*\(`),
		Severity:    entity.SeverityHigh,
		Category:    "JavaScript",
		Description: "PDF contains JavaScript eval() - common in exploits",
	},

	// Automatic execution (HIGH risk)
	{
		Name:        "OpenAction",
		Pattern:     regexp.MustCompile(`/OpenAction`),
		Severity:    entity.SeverityHigh,
		Category:    "AutoExecution",
		Description: "PDF has automatic action on document open",
	},
	{
		Name:        "Additional Actions",
		Pattern:     regexp.MustCompile(`/AA\s*<<`),
		Severity:    entity.SeverityMedium,
		Category:    "AutoExecution",
		Description: "PDF has additional automatic actions",
	},
	{
		Name:        "Page Open Action",
		Pattern:     regexp.MustCompile(`/O\s*/JavaScript`),
		Severity:    entity.SeverityHigh,
		Category:    "AutoExecution",
		Description: "PDF runs JavaScript when page opens",
	},

	// Launch actions (CRITICAL - can execute programs)
	{
		Name:        "Launch Action",
		Pattern:     regexp.MustCompile(`/Launch`),
		Severity:    entity.SeverityCritical,
		Category:    "Launch",
		Description: "PDF can launch external applications - DANGEROUS",
	},
	{
		Name:        "Windows Launch",
		Pattern:     regexp.MustCompile(`/Win\s*<<`),
		Severity:    entity.SeverityCritical,
		Category:    "Launch",
		Description: "PDF has Windows-specific launch action",
	},
	{
		Name:        "Unix Launch",
		Pattern:     regexp.MustCompile(`/Unix\s*<<`),
		Severity:    entity.SeverityCritical,
		Category:    "Launch",
		Description: "PDF has Unix-specific launch action",
	},
	{
		Name:        "Executable Reference",
		Pattern:     regexp.MustCompile(`(?i)/F\s*\([^)]*\.(exe|cmd|bat|ps1|sh|vbs|dll)`),
		Severity:    entity.SeverityCritical,
		Category:    "Launch",
		Description: "PDF references executable file",
	},

	// Embedded content (MEDIUM risk)
	{
		Name:        "Embedded Files",
		Pattern:     regexp.MustCompile(`/EmbeddedFiles`),
		Severity:    entity.SeverityMedium,
		Category:    "Embedded",
		Description: "PDF contains embedded files - may hide malware",
	},
	{
		Name:        "File Attachment",
		Pattern:     regexp.MustCompile(`/FileAttachment`),
		Severity:    entity.SeverityMedium,
		Category:    "Embedded",
		Description: "PDF has file attachment annotation",
	},
	{
		Name:        "Embedded Stream",
		Pattern:     regexp.MustCompile(`/EmbeddedFile`),
		Severity:    entity.SeverityMedium,
		Category:    "Embedded",
		Description: "PDF contains embedded file stream",
	},

	// External data operations (MEDIUM risk)
	{
		Name:        "Submit Form",
		Pattern:     regexp.MustCompile(`/SubmitForm`),
		Severity:    entity.SeverityMedium,
		Category:    "External",
		Description: "PDF can submit form data to external server",
	},
	{
		Name:        "Import Data",
		Pattern:     regexp.MustCompile(`/ImportData`),
		Severity:    entity.SeverityMedium,
		Category:    "External",
		Description: "PDF can import external data",
	},
	{
		Name:        "GoToR (Remote)",
		Pattern:     regexp.MustCompile(`/GoToR`),
		Severity:    entity.SeverityLow,
		Category:    "External",
		Description: "PDF references remote document",
	},
	{
		Name:        "GoToE (Embedded)",
		Pattern:     regexp.MustCompile(`/GoToE`),
		Severity:    entity.SeverityLow,
		Category:    "External",
		Description: "PDF navigates to embedded file",
	},

	// Suspicious URLs (MEDIUM risk)
	{
		Name:        "Suspicious URI",
		Pattern:     regexp.MustCompile(`/URI\s*\(\s*https?://[^)]*\.(ru|cn|xyz|top|tk|ml|ga|cf|gq|pw)/`),
		Severity:    entity.SeverityMedium,
		Category:    "URL",
		Description: "PDF contains URI to suspicious TLD",
	},
	{
		Name:        "Data URI",
		Pattern:     regexp.MustCompile(`/URI\s*\(\s*data:`),
		Severity:    entity.SeverityHigh,
		Category:    "URL",
		Description: "PDF contains data: URI scheme",
	},
	{
		Name:        "File URI",
		Pattern:     regexp.MustCompile(`/URI\s*\(\s*file:`),
		Severity:    entity.SeverityHigh,
		Category:    "URL",
		Description: "PDF references local file via URI",
	},

	// Obfuscation indicators (HIGH risk)
	{
		Name:        "Heavy Hex Encoding",
		Pattern:     regexp.MustCompile(`(#[0-9a-fA-F]{2}){20,}`),
		Severity:    entity.SeverityHigh,
		Category:    "Obfuscation",
		Description: "PDF contains heavily hex-encoded content - possible obfuscation",
	},
	{
		Name:        "Multiple Stream Filters",
		Pattern:     regexp.MustCompile(`/Filter\s*\[\s*(/\w+\s*){3,}\]`),
		Severity:    entity.SeverityMedium,
		Category:    "Obfuscation",
		Description: "PDF uses multiple stream filters - possible obfuscation",
	},
	{
		Name:        "AcroForm with JavaScript",
		Pattern:     regexp.MustCompile(`/AcroForm[^>]*(/JS|/JavaScript)`),
		Severity:    entity.SeverityHigh,
		Category:    "Obfuscation",
		Description: "PDF form contains JavaScript",
	},

	// Known exploit patterns (CRITICAL)
	{
		Name:        "Heap Spray Pattern",
		Pattern:     regexp.MustCompile(`(%u0a0a|\\x0a\\x0a){10,}`),
		Severity:    entity.SeverityCritical,
		Category:    "Exploit",
		Description: "Possible heap spray detected - common exploit technique",
	},
	{
		Name:        "NOP Sled",
		Pattern:     regexp.MustCompile(`(%u9090|\\x90\\x90){10,}`),
		Severity:    entity.SeverityCritical,
		Category:    "Exploit",
		Description: "NOP sled detected - indicates shellcode",
	},
	{
		Name:        "CVE Reference",
		Pattern:     regexp.MustCompile(`(?i)CVE-\d{4}-\d+`),
		Severity:    entity.SeverityMedium,
		Category:    "Exploit",
		Description: "PDF contains CVE reference - may be testing exploit",
	},

	// Suspicious stream content - only in context of execution
	{
		Name:        "PowerShell Execution",
		Pattern:     regexp.MustCompile(`(?i)(powershell\s*(-\w+\s+)*-[ecE]|IEX\s*\(|Invoke-Expression\s*\(|pwsh\s+-c)`),
		Severity:    entity.SeverityCritical,
		Category:    "Payload",
		Description: "PDF contains PowerShell execution commands",
	},
	{
		Name:        "Bash/Shell in PDF",
		Pattern:     regexp.MustCompile(`(?i)/bin/(ba)?sh|/dev/tcp|nc\s+-[elp]`),
		Severity:    entity.SeverityCritical,
		Category:    "Payload",
		Description: "PDF contains shell commands or reverse shell indicators",
	},
	{
		Name:        "Base64 Executable",
		Pattern:     regexp.MustCompile(`(?i)base64\s*-d|atob\s*\(`),
		Severity:    entity.SeverityHigh,
		Category:    "Payload",
		Description: "PDF decodes base64 content - possible hidden payload",
	},
	{
		Name:        "WScript/CScript",
		Pattern:     regexp.MustCompile(`(?i)wscript|cscript|\.vbs`),
		Severity:    entity.SeverityHigh,
		Category:    "Payload",
		Description: "PDF references Windows scripting",
	},
}

// NewPDFScanner creates a new PDF scanner
func NewPDFScanner() *PDFScanner {
	return &PDFScanner{
		BaseScanner: NewBaseScanner("pdf", "Scans for malicious PDF files"),
		scanPaths: []string{
			"/home",
			"/tmp",
			"/var/tmp",
			"/dev/shm",
			"/root",
		},
		maxFileSize: 50 * 1024 * 1024,  // 50MB max file size
		maxScanSize: 1 * 1024 * 1024,   // Scan first 1MB of each file
		concurrent:  5,                  // 5 concurrent file scans
	}
}

// NewPDFScannerWithPaths creates a PDF scanner with custom paths
func NewPDFScannerWithPaths(paths []string) *PDFScanner {
	scanner := NewPDFScanner()
	if len(paths) > 0 {
		scanner.scanPaths = paths
	}
	return scanner
}

// Scan performs the PDF malware scan
func (s *PDFScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.Logger().Info("starting PDF scanner")
	var findings []*entity.Finding
	var mu sync.Mutex

	// Find all PDF files
	pdfFiles, err := s.findPDFFiles(ctx)
	if err != nil {
		s.Logger().Error("failed to find PDF files", zap.Error(err))
		return findings, err
	}

	s.Logger().Info("found PDF files", zap.Int("count", len(pdfFiles)))

	// Scan files concurrently
	sem := make(chan struct{}, s.concurrent)
	var wg sync.WaitGroup

	for _, pdfFile := range pdfFiles {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()

			fileFindings := s.scanPDFFile(ctx, path)
			if len(fileFindings) > 0 {
				mu.Lock()
				findings = append(findings, fileFindings...)
				mu.Unlock()
			}
		}(pdfFile)
	}

	wg.Wait()

	s.Logger().Info("PDF scan complete",
		zap.Int("files_scanned", len(pdfFiles)),
		zap.Int("findings", len(findings)),
	)

	return findings, nil
}

// findPDFFiles locates PDF files in configured paths
func (s *PDFScanner) findPDFFiles(ctx context.Context) ([]string, error) {
	var pdfFiles []string
	var mu sync.Mutex

	for _, basePath := range s.scanPaths {
		// Check if path exists
		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			continue
		}

		err := filepath.WalkDir(basePath, func(path string, d os.DirEntry, err error) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if err != nil {
				return nil // Skip inaccessible paths
			}

			// Skip directories
			if d.IsDir() {
				// Skip common non-interesting directories
				name := d.Name()
				if name == ".git" || name == "node_modules" || name == ".cache" ||
					name == "__pycache__" || name == ".venv" || name == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}

			// Check if it's a PDF file (by extension first for speed)
			if !strings.HasSuffix(strings.ToLower(path), ".pdf") {
				return nil
			}

			// Get file info for size check
			info, err := d.Info()
			if err != nil {
				return nil
			}

			// Skip files that are too large
			if info.Size() > s.maxFileSize {
				s.Logger().Debug("skipping large PDF", zap.String("path", path), zap.Int64("size", info.Size()))
				return nil
			}

			// Skip empty files
			if info.Size() == 0 {
				return nil
			}

			mu.Lock()
			pdfFiles = append(pdfFiles, path)
			mu.Unlock()

			return nil
		})

		if err != nil && err != context.Canceled {
			s.Logger().Debug("error walking path", zap.String("path", basePath), zap.Error(err))
		}
	}

	return pdfFiles, nil
}

// scanPDFFile scans a single PDF file for malicious content
func (s *PDFScanner) scanPDFFile(ctx context.Context, path string) []*entity.Finding {
	var findings []*entity.Finding

	// Open file
	file, err := os.Open(path)
	if err != nil {
		s.Logger().Debug("cannot open PDF", zap.String("path", path), zap.Error(err))
		return findings
	}
	defer file.Close()

	// Verify PDF magic bytes
	magic := make([]byte, 5)
	if _, err := file.Read(magic); err != nil {
		return findings
	}
	if string(magic) != "%PDF-" {
		s.Logger().Debug("not a valid PDF", zap.String("path", path))
		return findings
	}

	// Reset to start
	if _, err := file.Seek(0, 0); err != nil {
		return findings
	}

	// Read file content (up to maxScanSize)
	content := make([]byte, s.maxScanSize)
	n, err := io.ReadFull(file, content)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		s.Logger().Debug("error reading PDF", zap.String("path", path), zap.Error(err))
		return findings
	}
	content = content[:n]

	// Also read as text for pattern matching
	file.Seek(0, 0)
	textContent := s.readPDFText(file, s.maxScanSize)

	// Combine binary and text content for scanning
	combinedContent := string(content) + "\n" + textContent

	// Check each pattern
	matchedPatterns := make(map[string]bool) // Deduplicate findings per file
	for _, pattern := range pdfPatterns {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if pattern.Pattern.MatchString(combinedContent) {
			key := pattern.Name + ":" + path
			if matchedPatterns[key] {
				continue
			}
			matchedPatterns[key] = true

			finding := entity.NewFinding(
				entity.CategoryPDF,
				pattern.Severity,
				"Malicious PDF: "+pattern.Name,
				pattern.Description,
			).WithPath(path).
				WithDetail("pattern_category", pattern.Category).
				WithDetail("pattern_name", pattern.Name)

			// Extract matched content for context (limited)
			if matches := pattern.Pattern.FindStringSubmatch(combinedContent); len(matches) > 0 {
				match := matches[0]
				if len(match) > 100 {
					match = match[:100] + "..."
				}
				finding.WithDetail("matched_content", match)
			}

			findings = append(findings, finding)
			s.Logger().Warn("malicious PDF pattern detected",
				zap.String("path", path),
				zap.String("pattern", pattern.Name),
				zap.String("severity", pattern.Severity.String()),
			)
		}
	}

	return findings
}

// readPDFText attempts to extract readable text from PDF for pattern matching
func (s *PDFScanner) readPDFText(r io.Reader, maxBytes int64) string {
	var sb strings.Builder
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), int(maxBytes))

	bytesRead := int64(0)
	for scanner.Scan() && bytesRead < maxBytes {
		line := scanner.Text()
		bytesRead += int64(len(line))

		// Extract text between parentheses (PDF string literals)
		for i := 0; i < len(line); i++ {
			if line[i] == '(' {
				depth := 1
				start := i + 1
				for j := start; j < len(line) && depth > 0; j++ {
					if line[j] == '(' && (j == 0 || line[j-1] != '\\') {
						depth++
					} else if line[j] == ')' && (j == 0 || line[j-1] != '\\') {
						depth--
						if depth == 0 {
							sb.WriteString(line[start:j])
							sb.WriteString(" ")
							i = j
						}
					}
				}
			}
		}

		// Also include the raw line for pattern matching
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	return sb.String()
}
