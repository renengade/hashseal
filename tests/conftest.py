import os

# 测试不写用户真实审计日志；需要测试审计的用例会临时清除该变量
os.environ.setdefault("HASHSEAL_NO_AUDIT", "1")
