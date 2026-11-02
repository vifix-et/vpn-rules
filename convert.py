import os
import json
import subprocess

# 目录配置
surge_dir = "surge"
singbox_dir = "sing-box"

os.makedirs(singbox_dir, exist_ok=True)

# 要处理的 4 个规则文件列表
files = [
    "reject-rules.list",
    "direct-rules.list",
    "emby-rules.list",
    "proxy-rules.list"
]

for filename in files:
    list_path = os.path.join(surge_dir, filename)
    if not os.path.exists(list_path):
        print(f"Skipped: {list_path} not found.")
        continue
    
    base_name = filename.replace(".list", "")
    json_path = os.path.join(singbox_dir, f"{base_name}.json")
    srs_path = os.path.join(singbox_dir, f"{base_name}.srs")
    
    domains = []
    domain_suffix = []
    domain_keyword = []
    ip_cidr = []
    
    # 解析 Surge 的纯文本规则
    with open(list_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # 过滤空行与注释
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            if "#" in line:
                line = line.split("#")[0].strip()
            if "//" in line:
                line = line.split("//")[0].strip()
                
            parts = line.split(",", 1)
            if len(parts) < 2:
                continue
            
            rule_type = parts[0].strip().upper()
            rule_value = parts[1].strip()
            
            # 【修复关键点】去除诸如 ,no-resolve 等 Surge 特有扩展参数
            if "," in rule_value:
                rule_value = rule_value.split(",")[0].strip()
            
            if rule_type == "DOMAIN":
                domains.append(rule_value)
            elif rule_type == "DOMAIN-SUFFIX":
                domain_suffix.append(rule_value)
            elif rule_type == "DOMAIN-KEYWORD":
                domain_keyword.append(rule_value)
            elif rule_type in ["IP-CIDR", "IP-CIDR6"]:
                ip_cidr.append(rule_value)
                
    # 构造 sing-box 规则集 JSON 结构
    rule_obj = {"version": 1, "rules": []}
    sub_rule = {}
    if domains:
        sub_rule["domain"] = domains
    if domain_suffix:
        sub_rule["domain_suffix"] = domain_suffix
    if domain_keyword:
        sub_rule["domain_keyword"] = domain_keyword
    if ip_cidr:
        sub_rule["ip_cidr"] = ip_cidr
        
    if sub_rule:
        rule_obj["rules"].append(sub_rule)
        
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(rule_obj, jf, indent=2, ensure_ascii=False)
        
    # 调用 sing-box 编译为二进制 .srs 文件
    subprocess.run(["sing-box", "rule-set", "compile", json_path, "-o", srs_path], check=True)
    
    # 清理中间生成的临时 JSON 文件
    if os.path.exists(json_path):
        os.remove(json_path)
        
    print(f"Successfully converted: {filename} -> {singbox_dir}/{base_name}.srs")
