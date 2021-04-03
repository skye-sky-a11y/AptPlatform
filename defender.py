import rules
import re
from concurrent.futures import ThreadPoolExecutor
from concurrent import futures

class Defender:
    def __init__(self, cmdLine):
        self.cmdLine = cmdLine
        self.rules = []

    def init_rules(self):
        self.rules += rules.attack_rules.get('pty_shell')
        self.rules += rules.attack_rules.get('clear_log')
        self.rules += rules.attack_rules.get('Privilege Escalation')

    def compare_rule(self, rule, cmdLine):
        if rule.get('regex'):
            if re.match(rule.get('regex'), cmdLine):
                # print(rule)
                return rule.get('type')

        elif rule.get('cmdLine') and re.match(rule.get('cmdLine'), cmdLine):
            return rule.get('type')
        else:
            return

    def defend(self, rule, cmdLine):
        if self.compare_rule(rule, cmdLine):
            return rule
        else:
            return

    def run(self):
        self.init_rules()
        # for rule in self.rules:
        #     self.defend(rule,self.cmdLine)
        with ThreadPoolExecutor(max_workers=30) as pool:
            future_tasks = []
            for rule in self.rules:
                future = pool.submit(self.defend, rule, self.cmdLine)
                future_tasks.append(future)
            task_iter = futures.as_completed(future_tasks)
            for future in task_iter:
                if future.result():
                    return future.result()


if __name__ == '__main__':
    cmd = 'cp /dev/null /var/log/wtmp'
    rs = []
    D = Defender(cmd)
    print(D.run())

