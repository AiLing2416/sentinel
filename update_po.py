import re

translations = {
    'Search connections…': '正在搜索连接…',
    'Shell': '终端',
    'SFTP': '文件传输 (SFTP)',
    'Copy Host': '复制主机地址',
    'Clear Host Key': '清除主机密钥',
    'Connections': '连接'
}

with open('po/zh_CN.po', 'r', encoding='UTF-8') as f:
    content = f.read()

for msgid, msgstr in translations.items():
    # Use regex to find msgid and the following msgstr, then replace msgstr
    pattern = re.compile(f'msgid "{msgid}"\nmsgstr ""')
    content = pattern.sub(f'msgid "{msgid}"\nmsgstr "{msgstr}"', content)

with open('po/zh_CN.po', 'w', encoding='UTF-8') as f:
    f.write(content)

print("PO file updated.")
