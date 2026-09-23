import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadCurationSnapshot } from './apply-payload-curation.mjs';

const root = process.cwd();
const outputDir = join(root, 'content-review');
const snapshot = loadCurationSnapshot(join(root, 'data', 'payloader.sqlite'));
const sourceById = new Map(snapshot.payloads.map(payload => [payload.id, payload]));
const text = (zh, en) => ({ zh, en });

const profiles = [
  {
    id: 'cloud-iam-escalation', labelZh: 'AWS IAM 权限边界', labelEn: 'AWS IAM Authorization Boundaries',
    targets: ['cloud-aws-pentest', 'aws-advanced-attacks', 'pacu'],
    rationale: '原条目由 AWS CLI 与 Pacu 命令组成，并混入创建 Lambda 和策略版本的状态变更步骤；迁入只读 AWS/Pacu 工具卡。',
  },
  {
    id: 'cloud-k8s-escape', labelZh: 'Kubernetes 容器边界', labelEn: 'Kubernetes Container Boundaries',
    targets: ['kubernetes-security', 'kubernetes-advanced'],
    rationale: '原条目由 kubectl、ServiceAccount 与宿主机挂载命令组成；迁入 Kubernetes 工具并替换为 RBAC、Admission 与 dry-run 检查。',
  },
  {
    id: 'cloud-s3-misconfig', labelZh: 'S3 配置审计', labelEn: 'S3 Configuration Audit',
    targets: ['cloud-aws-pentest', 'aws-advanced-attacks'],
    rationale: '原条目是 AWS CLI 桶枚举、下载和写入操作手册；迁入 S3 配置工具，仅保留 Head/Public Access Block/Policy Status 与有界列举。',
  },
  {
    id: 'cloud-ssrf-metadata', labelZh: '云元数据配置边界', labelEn: 'Cloud Metadata Configuration Boundaries',
    targets: ['cloud-aws-pentest', 'cloud-gcp-pentest'],
    rationale: '原条目混合元数据请求、导入临时凭据和数据下载；迁入 AWS/GCP 配置工具并只检查 IMDS/元数据防护状态。',
  },
];

for (const profile of profiles) if (!sourceById.has(profile.id)) throw new Error(`Missing source payload: ${profile.id}`);

const references = [
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
  'https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html',
  'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html',
  'https://kubernetes.io/docs/concepts/security/pod-security-standards/',
  'https://kubernetes.io/docs/reference/access-authn-authz/authorization/',
];

const overrides = {
  schemaVersion: 1,
  contentStandard: 2,
  sourceIds: profiles.map(profile => profile.id),
  entries: profiles.map(profile => ({
    id: profile.id,
    name: text(`${profile.labelZh}（工具迁移）`, `${profile.labelEn} (Tool Migration)`),
    description: text('该源条目是云 CLI 或框架操作手册，迁入对应 AWS、GCP 或 Kubernetes 工具卡后，不再作为独立 Payload 展示。', 'This source entry is a cloud CLI or framework operations manual and is migrated to the corresponding AWS, GCP, or Kubernetes tool cards instead of remaining a standalone payload.'),
    category: text('云安全工具工作流', 'Cloud Security Tool Workflows'),
    subCategory: text(profile.labelZh, profile.labelEn),
    prerequisites: [
      text('使用专用实验账号、最小权限 Profile、单一测试项目/集群和预算告警，记录区域、账号、集群 Context 与工具版本。', 'Use a dedicated lab identity, least-privilege profile, one test project or cluster, and budget alerts while recording region, account, cluster context, and tool versions.'),
      text('默认只读；任何 Admission dry-run 仍需固定命名空间和合成清单，禁止创建角色绑定、函数、访问密钥或公开桶。', 'Default to read-only operations; even admission dry-runs require a fixed namespace and synthetic manifest, with no role bindings, functions, access keys, or public buckets created.'),
    ],
    tutorial: {
      overview: text(`${profile.labelZh} 原卡片把多个云工具命令和状态变更步骤当成 Payload。迁移后只在工具区维护身份、Context、命令、证据和停止条件。`, `The original ${profile.labelEn} card treated multiple cloud-tool commands and state-changing steps as payloads. After migration, identity, context, commands, evidence, and stop conditions are maintained only in the tool section.`),
      vulnerability: text('云风险来自实际 IAM/RBAC 决策、资源策略、Public Access Block、IMDS 配置、Admission 控制和工作负载权限，不由 CLI 命令存在或返回列表证明。', 'Cloud risk comes from actual IAM or RBAC decisions, resource policies, Public Access Block, IMDS configuration, admission controls, and workload privileges rather than the existence of a CLI command or a returned list.'),
      exploitation: text('先确认当前身份和只读权限，再读取单一资源配置或运行授权判断；仅使用固定 lab 资源名和返回上限，不下载对象、Secret、Token 或用户数据。', 'Confirm the current identity and read-only permissions before reading one resource configuration or running an authorization decision, using fixed lab resource names and result limits without downloading objects, secrets, tokens, or user data.'),
      mitigation: text('应用最小权限、SCP/Permission Boundary、S3 Block Public Access、IMDSv2、Workload Identity、Pod Security Admission 和命名空间 RBAC，并用相同只读检查回归。', 'Apply least privilege, SCPs or permission boundaries, S3 Block Public Access, IMDSv2, workload identity, Pod Security Admission, and namespace RBAC, then regress the same read-only checks.'),
      difficulty: 'advanced',
    },
    attackChain: [
      { title: text('确认云身份与 Context', 'Confirm cloud identity and context'), description: text('从工具卡运行身份查询并记录账号、区域、项目或集群 Context。', 'Run the identity query from the tool card and record account, region, project, or cluster context.'), payloadRef: { area: 'execution', index: 0 } },
      { title: text('读取单一授权边界', 'Read one authorization boundary'), description: text('对固定 lab 资源运行只读策略、RBAC 或元数据配置检查。', 'Run a read-only policy, RBAC, or metadata-configuration check against one fixed lab resource.') },
      { title: text('关联日志并回归', 'Correlate logs and regress'), description: text('把 CLI 输出与 CloudTrail、Audit Log 或 Admission 结果关联，修复后重复相同检查。', 'Correlate CLI output with CloudTrail, audit logs, or admission results and repeat the same check after remediation.') },
    ],
    analysis: text('阳性需要当前身份、资源策略或授权决定与审计日志一致。命令成功、HTTP 200、资源名称存在、can-i 返回列表或工具报告标签都不能单独证明越权或逃逸。', 'A positive result requires the current identity, resource policy or authorization decision, and audit logs to agree. Command success, HTTP 200, a resource name, a can-i list, or a tool label alone does not prove privilege escalation or escape.'),
    opsecTips: [
      text('限制 API 页大小和调用次数，输出只写入 artifacts，不保存 Token、Secret、对象正文或 User Data。', 'Limit API page size and call count, write output only to artifacts, and do not retain tokens, secrets, object bodies, or user data.'),
      text('出现状态变更、预算异常、非实验资源或审计日志缺失时立即停止。', 'Stop immediately on state changes, budget anomalies, non-lab resources, or missing audit logs.'),
    ],
    references,
    review: {
      decision: 'tool', rationale: profile.rationale,
      issuesResolved: ['corrected-tool-classification', 'removed-state-changing-cloud-actions', 'removed-secret-and-token-reads', 'added-bounded-read-only-checks', 'added-authoritative-references'],
      targetToolIds: profile.targets,
    },
  })),
};

const migrations = {
  schemaVersion: 1,
  contentStandard: 2,
  toolMigrations: profiles.map(profile => ({
    sourceId: profile.id,
    targets: profile.targets.map(targetToolId => ({ targetToolId, navRootId: 'cloud-tools', commandIndexes: [] })),
    review: { rationale: profile.rationale, commandDisposition: 'covered-by-reviewed-cloud-tool-cards' },
  })),
};

const commandPatch = (index, value, zh, en) => [
  { path: `commands.${index}.command`, value },
  { path: `commands.${index}.description`, value: text(zh, en) },
];

const toolOverrides = {
  schemaVersion: 1,
  entries: [
    {
      id: 'kubernetes-security',
      patches: [
        { path: 'description', value: text('Kubernetes 只读安全审计命令，覆盖 RBAC、ServiceAccount 文件权限、命名空间资源、Pod Security Admission dry-run、API 健康与 etcd 端点状态。', 'Read-only Kubernetes security-audit commands covering RBAC, service-account file permissions, namespace resources, Pod Security Admission dry-runs, API health, and etcd endpoint status.') },
        ...commandPatch(0, 'kubectl auth can-i --list -n payloader-lab\nkubectl auth can-i create pods -n payloader-lab --as=system:serviceaccount:payloader-lab:auditor', '列出当前身份在固定命名空间的授权结果，并显式检查合成 ServiceAccount 是否可创建 Pod，不实际创建资源。', 'List authorization results for the current identity in one fixed namespace and explicitly test whether a synthetic service account may create pods without creating resources.'),
        ...commandPatch(1, 'stat -c "%a %U:%G %n" /var/run/secrets/kubernetes.io/serviceaccount/token /var/run/secrets/kubernetes.io/serviceaccount/ca.crt', '仅检查 ServiceAccount Token 与 CA 文件的权限、所有者和路径，不输出文件内容。', 'Inspect only permissions, ownership, and paths for service-account token and CA files without printing their contents.'),
        ...commandPatch(2, 'kubectl get --raw /version', '读取 Kubernetes API 版本作为连接基线，不手工读取或传递 ServiceAccount Token。', 'Read the Kubernetes API version as a connectivity baseline without manually reading or passing a service-account token.'),
        ...commandPatch(3, 'kubectl get pods,services,deployments -n payloader-lab -o wide\nkubectl auth can-i get secrets -n payloader-lab', '列出固定实验命名空间的非敏感工作负载元数据，并只询问 Secret 权限，不读取 Secret 名称或内容。', 'List non-sensitive workload metadata in one lab namespace and ask only whether secrets are readable without listing secret names or contents.'),
        ...commandPatch(4, 'kubectl apply --dry-run=server -n payloader-lab -f fixtures/privileged-pod.yaml -o yaml', '把合成特权 Pod 清单提交给服务端 Admission dry-run，记录拒绝原因且不持久化对象。', 'Submit a synthetic privileged-pod manifest to server-side admission dry-run and record rejection reasons without persisting an object.'),
        ...commandPatch(5, 'kubectl get --raw /api/v1/nodes/{LAB_NODE}/proxy/healthz', '读取登记实验节点的 kubelet healthz 代理响应，不执行容器命令或创建 Pod。', 'Read the kubelet healthz proxy response for one registered lab node without executing container commands or creating pods.'),
        ...commandPatch(6, 'ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 --cacert=fixtures/etcd/ca.crt --cert=fixtures/etcd/client.crt --key=fixtures/etcd/client.key endpoint status --write-out=table', '使用实验 mTLS 证书读取本地 etcd 端点状态，不枚举键或 Secret。', 'Read local etcd endpoint status with lab mTLS certificates without enumerating keys or secrets.'),
      ],
    },
    {
      id: 'kubernetes-advanced',
      patches: [
        { path: 'description', value: text('Kubernetes 高级授权边界审计，使用 can-i、只读 API 与工具帮助输出检查 kubelet、ServiceAccount 和集群级权限，不创建绑定或执行容器命令。', 'Advanced Kubernetes authorization-boundary auditing using can-i, read-only APIs, and tool help output for kubelet, service-account, and cluster-level permissions without creating bindings or executing container commands.') },
        ...commandPatch(0, 'kubectl auth can-i get nodes/proxy\nkubectl auth can-i create pods/exec -n payloader-lab', '检查当前身份是否可访问 node proxy 或 pods/exec 子资源，不向 kubelet 发起 exec 或 run 操作。', 'Check whether the current identity may access node proxy or pods/exec subresources without sending kubelet exec or run operations.'),
        ...commandPatch(1, 'kubectl auth can-i create clusterrolebindings.rbac.authorization.k8s.io\nkubectl auth can-i impersonate users', '只查询集群角色绑定创建权和用户模拟权，不创建 cluster-admin 绑定或导出 Token。', 'Query only cluster-role-binding creation and user-impersonation permissions without creating a cluster-admin binding or exporting tokens.'),
        ...commandPatch(2, 'peirates --help', '仅输出 Peirates 当前参数与版本，实际模块运行必须在单独批准的隔离集群任务中配置。', 'Print current Peirates options and version only; module execution requires a separately approved isolated-cluster task.'),
      ],
    },
  ],
};

for (const [name, value] of [
  ['overrides-cloud-workflows.json', overrides],
  ['collection-splits-cloud-workflows.json', migrations],
  ['tool-overrides-quality-kubernetes.json', toolOverrides],
]) {
  writeFileSync(join(outputDir, name), `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  console.log(`wrote ${name}`);
}
