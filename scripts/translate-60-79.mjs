import { DatabaseSync } from 'node:sqlite';
const db = new DatabaseSync('C:/Users/Hezihao/Desktop/payloader/data/payloader.sqlite');
const sel = db.prepare('SELECT data FROM payloads WHERE id=?');
const upd = db.prepare("UPDATE payloads SET data=?, updated_at=datetime('now') WHERE id=?");

const trans = [
  {
    id: 'xxe-blind',
    ov_en: 'Blind XXE refers to scenarios where XML external entity injection succeeds but the entity content is not directly reflected in the response. It requires out-of-band (OOB) data exfiltration techniques to send the file contents to an attacker-controlled server via HTTP/DNS.',
    vu_en: 'Blind XXE leverages parameter entities (%entity) and external DTDs to exfiltrate data: nested entity references are defined in an external DTD, and file contents are appended to an HTTP request URL sent to the attacker\'s server. Some XML parsers restrict entity nesting, requiring different exfiltration strategies.',
    ex_en: 'Full exploitation workflow:\n1. Confirm XXE exists\n2. Use parameter entities\n3. Construct OOB out-of-band channel\n4. Retrieve sensitive data',
    mi_en: 'Defending against Blind XXE: disable XML external entities and DTD processing (most effective), use JSON instead of XML, configure network-layer egress whitelists to block OOB exfiltration, deploy WAF to detect DTD declarations and entity references, monitor anomalous DNS/HTTP outbound requests.'
  },
  {
    id: 'xxe-oob',
    ov_en: 'XXE OOB (Out-of-Band) data exfiltration is the core exploitation technique for Blind XXE. It transmits server-internal data to the attacker via external channels such as HTTP/FTP/DNS, and is the key step from XXE detection to actual data extraction.',
    vu_en: 'XXE OOB is achieved via multi-layer parameter entity nesting: 1) the first entity reads the target file; 2) the second entity (external DTD) appends the file content into an HTTP URL; 3) the parser requests that URL, sending data to the attacker. FTP can exfiltrate multi-line content; DNS serves as a covert channel in strict network environments.',
    ex_en: 'Full exploitation workflow:\n1. Host a malicious DTD file\n2. Construct an XXE payload\n3. Trigger the out-of-band request\n4. Receive and parse the exfiltrated data',
    mi_en: 'Defending against XXE OOB: completely disable external entity processing and DTD loading, enforce strict egress network policies (allow only necessary whitelisted outbound connections), monitor anomalous DNS queries and HTTP outbound requests, use RASP to detect file access and network requests during XML parsing.'
  },
  {
    id: 'xxe-ssrf',
    ov_en: 'XXE SSRF uses XML external entities to issue server-side requests, enabling probing and access to internal network services, cloud metadata APIs, and local ports — extending the impact of an XXE vulnerability from the XML parser\'s host server to the entire internal network.',
    vu_en: 'XXE SSRF references internal URLs via SYSTEM entities: <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/"> to retrieve cloud metadata, http://internal-service:8080/admin to access internal management interfaces, and http://127.0.0.1:port/ for port scanning.',
    ex_en: 'Full exploitation workflow:\n1. Discover the XXE vulnerability\n2. Construct an SSRF payload\n3. Access internal services\n4. Retrieve sensitive information',
    mi_en: 'Defending against XXE SSRF: disable external entity processing, configure network segmentation to restrict the XML parsing server\'s network access, block requests to the metadata service (169.254.169.254), enable IMDSv2 (AWS) to require token authentication, monitor anomalous intranet HTTP requests.'
  },
  {
    id: 'xxe-rce',
    ov_en: 'XXE remote code execution can be achieved in specific environments: PHP\'s expect:// protocol executes commands directly, WebShell files can be written via XXE, XXE SSRF can indirectly achieve RCE by attacking internal services (e.g., Redis), and XXE can be combined with Java deserialization attacks.',
    vu_en: 'XXE RCE exploitation paths: 1) PHP expect:// wrapper (<!ENTITY rce SYSTEM "expect://whoami">); 2) combined with file upload to write a WebShell; 3) XXE SSRF → gopher:// to attack internal Redis/MySQL for RCE; 4) triggering deserialization vulnerabilities in Java environments via XXE.',
    ex_en: 'Full exploitation workflow:\n1. Confirm the expect extension is available\n2. Construct an expect:// protocol payload\n3. Execute system commands\n4. Obtain a shell',
    mi_en: 'Defending against XXE RCE: disable external entities and all PHP stream wrappers, remove unnecessary PHP extensions (e.g., expect), enforce strict filesystem permissions to prevent writes to the web directory, isolate the network to restrict the XML parsing server\'s access, and regularly update XML parsing libraries.'
  },
  {
    id: 'xxe-file-read',
    ov_en: 'XXE file read is the most fundamental exploitation method for XXE vulnerabilities. It reads local server files by defining an external entity using the file:// protocol. The direct-echo method allows file contents to be seen in the response and is the first step in XXE validation and information gathering.',
    vu_en: 'XXE file read uses the file:// protocol: <!ENTITY file SYSTEM "file:///etc/passwd">. Key files that can be read include system configs (/etc/passwd, /etc/hosts), application source code, database configs (with passwords), SSH keys, etc. Binary files require PHP\'s php://filter/base64 for encoded reading.',
    ex_en: 'Full exploitation workflow:\n1. Discover the XXE vulnerability\n2. Construct a file-read payload\n3. Read sensitive files\n4. Obtain credentials',
    mi_en: 'Defending against XXE file read: disable external entities in the XML parser configuration (e.g., Java\'s setFeature DISALLOW_DOCTYPE), use secure XML libraries (e.g., defusedxml for Python), minimize the system privileges of the XML parsing process, and set sensitive file permissions to owner-read-only.'
  },
  {
    id: 'xxe-dtd',
    ov_en: 'XXE DTD attacks exploit the entity declaration feature in Document Type Definitions (DTD), defining and leveraging malicious entities via internal DTDs or by loading external DTD files. The external DTD approach can bypass some parsers\' restrictions on parameter entity nesting within internal DTDs.',
    vu_en: 'XXE DTD exploitation methods: 1) internal DTD directly declares a SYSTEM entity to read files; 2) external DTD loads a malicious DTD file hosted on the attacker\'s server; 3) repurposes local DTD files to redefine entities (for environments that forbid loading external DTDs); 4) parameter entity nesting for complex data exfiltration.',
    ex_en: 'Full exploitation workflow:\n1. Create a malicious DTD file\n2. Host it on the attacker\'s server\n3. Construct an XXE reference to the DTD\n4. Trigger out-of-band exfiltration to retrieve data',
    mi_en: 'Defending against XXE DTD: completely disable DTD processing (disallow-doctype-decl=true), prohibit loading external DTD files, if DTD must be used allow only specific local DTDs, use WAF to detect and block XML requests containing DOCTYPE declarations, use lightweight XML parsing modes that do not support DTD.'
  },
  {
    id: 'xxe-xlsx',
    ov_en: 'XLSX files are essentially ZIP archives containing multiple XML files. Uploading a malicious XLSX file can trigger XXE vulnerabilities in the server-side XML parser. Office document processing, data import, and reporting system features are common attack entry points.',
    vu_en: 'XLSX XXE exploitation steps: unzip the XLSX file → inject XXE entity declarations into XML files such as xl/workbook.xml or [Content_Types].xml → recompress as XLSX → upload to the target system. When the server uses an insecure XML parser to process the XLSX, XXE is triggered to read files or perform SSRF.',
    ex_en: 'Full exploitation workflow:\n1. Unzip the XLSX file\n2. Inject the XXE payload\n3. Repackage the file\n4. Upload to trigger the vulnerability',
    mi_en: 'Defending against XLSX XXE: use securely configured XML parsing libraries to process Office documents, validate XLSX file structure and strip DTD declarations before parsing, use dedicated Office document processing libraries (e.g., Apache POI configured to disable external entities), perform sandbox parsing of uploaded files.'
  },
  {
    id: 'xxe-docx',
    ov_en: 'DOCX files, like XLSX, are Office Open XML format based on XML. By modifying the XML files within them to inject XXE entities, server-side XXE vulnerabilities can be triggered in document processing systems (online preview, format conversion, content extraction).',
    vu_en: 'DOCX XXE injection points include: word/document.xml (main document content), [Content_Types].xml (content type definitions), word/_rels/.rels (relationship definitions), and other XML files. Online document preview services, file format conversion APIs, and resume parsing systems are high-risk attack surfaces.',
    ex_en: 'Full exploitation workflow:\n1. Unzip the DOCX file\n2. Inject the XXE payload\n3. Repackage the file\n4. Upload to trigger the vulnerability',
    mi_en: 'Defending against DOCX XXE: same as XLSX defense — use securely configured XML parsers, disable external entities, preprocess user-uploaded Office documents (strip DTD/entity declarations), process untrusted documents in an isolated environment, restrict the document processing process\'s network and file access permissions.'
  },
  {
    id: 'graphql-injection',
    ov_en: 'GraphQL injection attacks exploit the flexibility of the GraphQL query language for information disclosure and data manipulation, including deeply nested queries (DoS), field suggestion leakage of schema information, variable injection to bypass query restrictions, and batch queries via aliases.',
    vu_en: 'GraphQL-specific vulnerabilities: 1) nested query DoS (deep nesting causes exponential database queries); 2) field suggestion leakage (similar field names returned on typos); 3) alias batch queries (thousands of records in a single request); 4) variable type mismatch bypassing input validation; 5) directive injection (@skip/@include abuse).',
    ex_en: 'Full exploitation workflow:\n1. Probe the GraphQL endpoint\n2. Execute introspection queries to retrieve the API structure\n3. Analyze sensitive fields and operations\n4. Construct injection payloads\n5. Use batch queries to bypass restrictions',
    mi_en: 'Defensive measures:\n1. Disable introspection in production\n2. Implement input validation\n3. Limit query depth and complexity\n4. Enforce authentication and authorization\n5. Restrict batch queries'
  },
  {
    id: 'graphql-introspection',
    ov_en: 'GraphQL Introspection is a built-in schema self-description feature of the GraphQL specification, allowing clients to query the complete type system, field definitions, and parameter information of an API. When not disabled in production, it will expose all API structural information.',
    vu_en: 'GraphQL introspection via __schema/__type queries returns: all type and field definitions, the complete interfaces for Query/Mutation/Subscription, field arguments and return types, enum values, interfaces and union types — equivalent to leaking the full API documentation.',
    ex_en: 'Full exploitation workflow:\n1. Send an introspection query\n2. Analyze the returned API structure\n3. Identify sensitive operations and fields\n4. Construct malicious queries',
    mi_en: 'Defending against GraphQL introspection leakage: disable introspection queries in production (most GraphQL frameworks support configuration), enforce access control on __schema/__type queries (admin-only), use query whitelists (Persisted Queries) to restrict executable queries, deploy a GraphQL gateway for query analysis.'
  },
  {
    id: 'graphql-batching',
    ov_en: 'GraphQL batching allows multiple query operations to be sent in a single HTTP request. Attackers can exploit this to bypass request-frequency-based rate limits, perform brute-force attacks (OTP/password), or issue bulk data queries.',
    vu_en: 'GraphQL batch query attacks: 1) send thousands of mutation operations in one request to brute-force OTPs/passwords (bypassing request-level rate limits); 2) use aliases in a single query to batch-query data for different users; 3) array-form batch queries ([{query1},{query2},...]) to evade authentication retry detection.',
    ex_en: 'Full exploitation workflow:\n1. Test whether batch queries are supported\n2. Use aliases or array-form batch queries\n3. Bypass rate limits\n4. Perform bulk enumeration or brute force',
    mi_en: 'Defensive measures:\n1. Limit the number of batch queries\n2. Rate-limit based on query complexity\n3. Enforce query depth limits\n4. Monitor anomalous query patterns'
  },
  {
    id: 'rest-api-security',
    ov_en: 'REST API security testing focuses on authentication/authorization flaws, insufficient input validation, excessive data exposure in responses, and missing rate limits. As the core of modern applications, API security directly affects the data security of the entire business system.',
    vu_en: 'Common REST API vulnerabilities: 1) missing authentication (API endpoints accessible without auth); 2) BOLA/IDOR (accessing others\' resources by iterating IDs); 3) Mass Assignment (submitting extra fields to modify permissions); 4) excessive data exposure (responses include unnecessary sensitive fields); 5) missing rate limits.',
    ex_en: 'Full exploitation workflow:\n1. Discover API endpoints and documentation\n2. Test authentication mechanisms\n3. Test HTTP methods\n4. Test parameter handling\n5. Test content types\n6. Look for injection points',
    mi_en: 'Defensive measures:\n1. Enforce strict authentication and authorization\n2. Restrict HTTP methods\n3. Input validation and filtering\n4. Rate limiting\n5. API versioning\n6. Secure CORS configuration'
  },
  {
    id: 'jwt-none-alg',
    ov_en: 'The JWT None algorithm attack exploits certain JWT libraries that accept tokens with the alg field set to "none" (meaning no signature verification is required). The attacker changes the token\'s algorithm to none, removes the signature, modifies claims in the payload (e.g., elevating role), and bypasses authentication.',
    vu_en: 'JWT None algorithm vulnerability: 1) change the alg in the Header to "none"/"None"/"NONE"/"nOnE" or other variants; 2) remove or empty the third part of the token (signature); 3) modify Payload claims (user role/ID/permissions); 4) re-encode with Base64 and send. Libraries that support the none algorithm will skip signature verification.',
    ex_en: 'Full exploitation workflow:\n1. Obtain a valid JWT token\n2. Decode and analyze the token structure\n3. Change the algorithm to none\n4. Modify the payload to escalate privileges\n5. Remove or retain an empty signature\n6. Send the malicious token',
    mi_en: 'Defensive measures:\n1. Disable the none algorithm\n2. Strictly validate the algorithm type\n3. Use a mature JWT library\n4. Verify that the signature is not empty\n5. Set a token expiration time'
  },
  {
    id: 'jwt-key-confusion',
    ov_en: 'JWT key confusion (Algorithm Confusion) attack changes the RS256 (asymmetric) signature to HS256 (symmetric), then uses the public key (usually obtainable) as the HMAC key to sign the token. If the server validates using the same key variable, the attack succeeds.',
    vu_en: 'JWT key confusion attack principle: RS256 signs with a private key / verifies with a public key; HS256 uses a shared key for both signing and verifying. When server-side code uses a generic "key" variable (storing the public key) for verification, the attacker changes alg to HS256 and signs the token with the public key (obtainable from /jwks.json or an X509 certificate) to pass verification.',
    ex_en: 'Full exploitation workflow:\n1. Obtain the target\'s public key\n2. Change the algorithm from RS256 to HS256\n3. Sign the token using the public key as the HMAC key\n4. Send the malicious token',
    mi_en: 'Defensive measures:\n1. Explicitly specify allowed algorithms\n2. Do not trust the alg field in the JWT\n3. Use a whitelist to validate algorithms\n4. Separate public key and symmetric key verification logic'
  },
  {
    id: 'api-idor',
    ov_en: 'IDOR (Insecure Direct Object Reference) is one of the most common high-severity vulnerabilities in APIs. Attackers access or manipulate other users\' resources by modifying object identifiers (user IDs, order numbers, filenames) in requests.',
    vu_en: 'IDOR vulnerability manifestations: 1) horizontal privilege escalation (GET /api/users/1001 → /api/users/1002 to view others\' profiles); 2) vertical privilege escalation (regular user accessing admin endpoints); 3) missing object-level authorization (modifying/deleting others\' resources); 4) predictable IDs (auto-increment numbers/UUIDs are enumerable); 5) bulk IDOR (iterating to export data).',
    ex_en: 'Full exploitation workflow:\n1. Identify API endpoints that use IDs\n2. Test with your own account\n3. Enumerate other ID values\n4. Verify access to other users\' data\n5. Bulk-enumerate sensitive data',
    mi_en: 'Defensive measures:\n1. Implement object-level authorization checks\n2. Use unpredictable IDs (UUID)\n3. Verify user ownership of resources\n4. Log anomalous access patterns\n5. Implement rate limiting'
  },
  {
    id: 'api-rate-limit',
    ov_en: 'Missing API rate limiting allows attackers to call API endpoints without restriction, potentially leading to brute-force attacks (passwords/OTPs), bulk data scraping, resource abuse (sending large numbers of SMS/emails), and denial of service.',
    vu_en: 'API rate limit bypass methods: 1) completely absent rate limiting (unlimited calls); 2) IP-only limiting (bypass by changing IP/using proxies); 3) user-only limiting (create multiple accounts); 4) limiting only certain endpoints (find unrestricted equivalent endpoints); 5) HTTP method switching (GET→POST); 6) adding request parameters to bypass signature checks.',
    ex_en: 'Full exploitation workflow:\n1. Detect the rate limit threshold\n2. Analyze what the limit is based on (IP/user/key)\n3. Choose an appropriate bypass method\n4. Execute a brute-force attack',
    mi_en: 'Defensive measures:\n1. Rate-limit based on user + IP combination\n2. Do not trust client IP headers\n3. Use sliding window rate limiting\n4. Implement CAPTCHA\n5. Monitor anomalous access patterns'
  },
  {
    id: 'api-mass-assignment',
    ov_en: 'Mass Assignment vulnerabilities occur when an API automatically binds request parameters to a data model. Attackers modify attributes that should not be user-controlled by submitting extra fields (e.g., role=admin, is_verified=true).',
    vu_en: 'Mass Assignment vulnerability scenarios: 1) adding role:admin during user registration to escalate privileges; 2) adding balance:999999 when updating a profile to alter balance; 3) modifying price:0 when creating an order; 4) adding is_admin:true when updating settings to gain admin access. The root cause is frameworks\' automatic binding features (e.g., Spring/Rails).',
    ex_en: 'Full exploitation workflow:\n1. Send a normal request and observe response fields\n2. Identify sensitive fields (role, isAdmin, etc.)\n3. Add sensitive fields to the request\n4. Verify whether the modification succeeded',
    mi_en: 'Defensive measures:\n1. Use DTOs (Data Transfer Objects)\n2. Whitelist allowed fields\n3. Configure object mapping libraries properly\n4. Validate and filter input'
  },
  {
    id: 'api-bola',
    ov_en: 'BOLA (Broken Object Level Authorization) is the #1 vulnerability in the OWASP API Top 10. It refers to APIs lacking proper authorization checks at the object level, allowing authenticated users to access or manipulate resource objects that do not belong to them.',
    vu_en: 'BOLA is closely related to IDOR but emphasizes authorization flaws: 1) API only verifies the user is logged in without verifying object ownership; 2) ID traversal allows bulk retrieval of all user data; 3) in GraphQL, arbitrary objects can be accessed directly via node IDs; 4) missing authorization on associated objects (accessing sub-resources belonging to others).',
    ex_en: 'Full exploitation workflow:\n1. Identify APIs that use object IDs\n2. Create multiple test accounts\n3. Test cross-account access\n4. Enumerate other objects\n5. Attempt modification/deletion operations',
    mi_en: 'Defensive measures:\n1. Implement object-level authorization checks\n2. Verify user ownership of resources\n3. Use unpredictable IDs\n4. Log anomalous access\n5. Implement rate limiting'
  },
  {
    id: 'api-injection',
    ov_en: 'API injection attacks apply traditional injection techniques (SQL/NoSQL/OS command/LDAP, etc.) to API interfaces. JSON/XML format input parameters, query strings, and HTTP headers can all become injection points, and APIs often lack the WAF protection that web applications have.',
    vu_en: 'API injection attack surface: 1) SQL/NoSQL injection in JSON parameters; 2) injection in GraphQL query variables; 3) header injection at API gateways/middleware (Host/X-Forwarded-For); 4) command injection in filename/path parameters; 5) LDAP/XPath query parameter injection; 6) stored XSS in API responses.',
    ex_en: 'Full exploitation workflow:\n1. Identify input points\n2. Analyze the backend tech stack\n3. Choose the appropriate injection type\n4. Construct an injection payload\n5. Extract data or execute commands',
    mi_en: 'Defensive measures:\n1. Use parameterized queries\n2. Input validation and whitelisting\n3. Principle of least privilege\n4. Do not leak information in error messages\n5. WAF protection'
  },
  {
    id: 'spring-spel',
    ov_en: 'Spring Expression Language (SpEL) injection is a critical vulnerability in the Spring framework that allows attackers to execute arbitrary Java code in a SpEL expression context. Affected components include Spring MVC, Spring Cloud, Spring Data, and more.',
    vu_en: 'SpEL injection executes system commands via T(java.lang.Runtime).getRuntime().exec(), or loads remote classes via ClassLoader. Trigger points include: Spring Cloud Gateway route predicates/filters, Spring Data @Value annotations, Thymeleaf preprocessing expressions, and Spring Security OAuth error handling.',
    ex_en: 'Full exploitation workflow:\n1. Probe the SpEL injection point\n2. Confirm expression execution\n3. Use Runtime to execute commands\n4. Read sensitive files or obtain a reverse shell',
    mi_en: 'Defensive measures:\n1. Avoid using user input directly in expressions\n2. Use SimpleEvaluationContext\n3. Input validation and filtering\n4. Upgrade Spring version'
  }
];

let n = 0;
for (const t of trans) {
  const row = sel.get(t.id);
  if (!row) continue;
  const p = JSON.parse(row.data);
  if (!p.tutorial) continue;
  if (t.ov_en) p.tutorial.overview = { zh: p.tutorial.overview?.zh || '', en: t.ov_en };
  if (t.vu_en) p.tutorial.vulnerability = { zh: p.tutorial.vulnerability?.zh || '', en: t.vu_en };
  if (t.ex_en) p.tutorial.exploitation = { zh: p.tutorial.exploitation?.zh || '', en: t.ex_en };
  if (t.mi_en) p.tutorial.mitigation = { zh: p.tutorial.mitigation?.zh || '', en: t.mi_en };
  upd.run(JSON.stringify(p), t.id);
  n++;
}
db.close();
console.log('updated:' + n);
