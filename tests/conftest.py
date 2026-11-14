import os
import tempfile

# 测试把审计日志写到临时目录，避免污染用户状态；日志本身始终开启
os.environ.setdefault(
    "HASHSEAL_AUDIT_LOG",
    os.path.join(tempfile.mkdtemp(prefix="hashseal-test-audit-"), "audit.jsonl"),
)
