from faker import Faker
import pexpect
import random




def generate_fake_user_attempt():
    fake = Faker()
    username = fake.user_name()
    password = fake.password()
    
    number = fake.random_int(min=1, max=20)
    for i in range(number):
        try:
            child = pexpect.spawn(f"ssh {username}@localhost", timeout=10)
            i = child.expect([pexpect.TIMEOUT, "password:", "yes/no", pexpect.EOF])
            if i == 1:
                child.sendline(password)
                child.expect(pexpect.EOF, timeout=5)
            elif i == 2:
                child.sendline('yes')
                child.expect('password:')
                child.sendline(password)
                child.expect(pexpect.EOF, timeout=5)
            child.close()
        except Exception:
            pass

def generate_real_user_attempt(username, password):
    try:
        child = pexpect.spawn(f"ssh {username}@localhost", timeout=10)
        i = child.expect([pexpect.TIMEOUT, "password:", "yes/no", pexpect.EOF])
        if i == 1:
            child.sendline(password)
            child.expect(pexpect.EOF, timeout=5)
        elif i == 2:
            child.sendline('yes')
            child.expect('password:')
            child.sendline(password)
            child.expect(pexpect.EOF, timeout=5)
        child.close()
    except Exception:
        pass
    
    
def generate_fake_sudo_attempt():
    fake = Faker()
    password = fake.password()
    
    number = fake.random_int(min=1, max=5)
    for i in range(number//2):
        try:
            child = pexpect.spawn(f"sudo ls", timeout=10)
            i = child.expect([pexpect.TIMEOUT, "password for", pexpect.EOF])
            if i == 1:
                child.sendline(password)
                child.expect(pexpect.EOF, timeout=5)
            child.close()
        except Exception:
            pass
    for i in range(number//2, number):
        try:
            child = pexpect.spawn(f"sudo bash", timeout=10)
            i = child.expect([pexpect.TIMEOUT, "password for", pexpect.EOF])
            if i == 1:
                child.sendline("wrongpassword")
                child.expect(pexpect.EOF, timeout=5)
            child.close()
        except Exception:
            pass
        
def generate_real_sudo_attempt(password):
    try:
        child = pexpect.spawn(f"sudo ls", timeout=10)
        i = child.expect([pexpect.TIMEOUT, "password for", pexpect.EOF])
        if i == 1:
            child.sendline(password)
            child.expect(pexpect.EOF, timeout=5)
        child.close()
    except Exception:
        pass



def main():
    actions = [
        generate_fake_user_attempt,
        generate_real_user_attempt,
        generate_fake_sudo_attempt,
        generate_real_sudo_attempt,
    ]

    selected_count = random.randint(1, len(actions))
    selected_actions = random.sample(actions, selected_count)

    for action in selected_actions:
        if action is generate_real_user_attempt:
            action("casper", "casper321")##change on your system
        elif action is generate_real_sudo_attempt:
            action("casper321")
        else:
            action()
    
if __name__ == "__main__":
    main()
