import subprocess, sys, os


def npm_install():
    open("npm_install_invoked","w+").close()
    return subprocess.Popen(["npm", "install"], cwd="Go-Crypto-Currency-Client/")


def run_backend(port):
    return subprocess.Popen(["./main", str(port)])

def run_frontend(port, conf):
    if conf != 0:
        return subprocess.Popen(['ng', 'serve', '--port', str(port), '-c', 'env' + str(conf)], cwd="Go-Crypto-Currency-Client/")
    else:
        return subprocess.Popen(['ng', 'serve', '--port', str(port)], cwd="Go-Crypto-Currency-Client/")

if __name__ == '__main__':
    try:
        if not os.path.exists("npm_install_invoked"):
            npm_install_proc = npm_install()
            npm_install_proc.communicate()
        conf = int(sys.argv[1])
        backend_port = 9000 + conf
        frontend_port = 4200 + conf
        print("CONF NUMBER = ", conf)
        backend_proc = run_backend(backend_port)
        frontend_proc = run_frontend(frontend_port, conf)
        backend_proc.communicate()
        frontend_proc.communicate()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            backend_proc.kill()
            frontend_proc.kill()
            sys.exit(0)
        except SystemExit:
            backend_proc.kill()
            frontend_proc.kill()
            os._exit(0)
