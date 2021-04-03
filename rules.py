attack_rules={
    'pty_shell': [
        {'cmdLine':'','type': "pty_shell",'regex': 'python -c [\'\"]import pty;pty.spawn\("/bin/bash"\)[\',\"]','type_info':'交互式shell命令执行'}
    ],
    'clear_log':[
        {'cmdLine': '','type': '清理日志记录','regex': 'cp /dev/null /var/log/wtmp','type_info':'清除last记录'},
        {'cmdLine': "",'type': "清理日志记录",'regex': 'export\\sHISTSIZE\\s{0,1}=0|export HISTFILE=/dev/','type_info':'清除history记录'}
    ],

    'Privilege Escalation':[
        {'cmdLine': '','type': '提权','regex': '^dd if=/dev/zero of=(.*) bs=10[m,M] count=10','type_info':'Kernel <= 2.6.17.4 Local Root Exploit'}
    ]
}
