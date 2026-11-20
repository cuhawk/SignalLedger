package compliance

type control struct {
	framework       string
	id              string
	title           string
	rules           []string
	approval        bool
	logging         bool
	missingEvidence string
}

const (
	iso   = "ISO/IEC 42001:2023"
	eu    = "EU AI Act"
	llm   = "OWASP Top 10 for LLM Applications 2025"
	agent = "OWASP Top 10 for Agentic Applications 2026"
)

var accessRules = []string{
	"cloudtrail_root_access_key", "distributed_password_spray", "impossible_travel", "mfa_fatigue",
	"okta_proxy_login", "password_spray", "scope_escalation", "token_replay",
}

var controls = []control{
	{framework: iso, id: "A.6", title: "AI system life cycle", rules: accessRules},
	{framework: iso, id: "A.8", title: "Information for interested parties", logging: true, missingEvidence: "interested_party_communication_evidence_required"},
	{framework: iso, id: "A.9", title: "Use of AI systems", rules: accessRules, approval: true},
	{framework: iso, id: "A.10", title: "Third-party and customer relationships", rules: []string{"scope_escalation"}, missingEvidence: "third_party_responsibility_evidence_required"},
	{framework: eu, id: "Article 12", title: "Record-keeping", logging: true},
	{framework: eu, id: "Article 14", title: "Human oversight", approval: true},
	{framework: eu, id: "Article 15", title: "Accuracy, robustness and cybersecurity", rules: accessRules},
	{framework: llm, id: "LLM01", title: "Prompt Injection"},
	{framework: llm, id: "LLM02", title: "Sensitive Information Disclosure"},
	{framework: llm, id: "LLM03", title: "Supply Chain"},
	{framework: llm, id: "LLM04", title: "Data and Model Poisoning"},
	{framework: llm, id: "LLM05", title: "Improper Output Handling"},
	{framework: llm, id: "LLM06", title: "Excessive Agency", approval: true},
	{framework: llm, id: "LLM07", title: "System Prompt Leakage"},
	{framework: llm, id: "LLM08", title: "Vector and Embedding Weaknesses"},
	{framework: llm, id: "LLM09", title: "Misinformation"},
	{framework: llm, id: "LLM10", title: "Unbounded Consumption"},
	{framework: agent, id: "ASI01", title: "Agent Goal Hijack"},
	{framework: agent, id: "ASI02", title: "Tool Misuse and Exploitation", approval: true},
	{framework: agent, id: "ASI03", title: "Identity and Privilege Abuse", rules: accessRules, approval: true},
	{framework: agent, id: "ASI04", title: "Agentic Supply Chain Vulnerabilities"},
	{framework: agent, id: "ASI05", title: "Unexpected Code Execution"},
	{framework: agent, id: "ASI06", title: "Memory and Context Poisoning"},
	{framework: agent, id: "ASI07", title: "Insecure Inter-Agent Communication"},
	{framework: agent, id: "ASI08", title: "Cascading Failures"},
	{framework: agent, id: "ASI09", title: "Human-Agent Trust Exploitation"},
	{framework: agent, id: "ASI10", title: "Rogue Agents"},
}
