import subprocess

def print_log(n):
    try:
        result = subprocess.run(['tail', f'-n{n}', '../logs/log.txt'], capture_output=True, text=True)

        if result.returncode == 0:
            print(result.stdout)
        else:
            print("Error:", result.stderr)
    except Exception as e:
        print("An error occurred:", e)
