"""A simple Python wrapper to create, select, scan with, and delete Axiom fleets."""
#https://twitter.com/similardisaster
#----------------------------------------------------------------------------------------------------------------------------------#
from shutil import which
from textwrap import dedent
from functools import wraps
from subprocess import run, PIPE
from shlex import split
#----------------------------------------------------------------------------------------------------------------------------------#

class Axiomy():


    """Initialize instance: 'axiom = Axiomy()'
    Create fleet 'foo' with 3 instances: 'axiom.fleet("foo", 3)'
    Run Amass scan: 'axiom.scan("/home/ubuntu/targets.txt", "amass")'
    Delete all instances in 'foo' fleet: 'axiom.rm("foo", wildcard = True)'"""

    ERROR_MESSAGE = """
                    Axiom is either incorectlly installed or not installed on this machine.
                    (You need to be running Zsh as your shell to run Axiom.)
                    You can build it manually by pasting the following into your terminal:

                    bash <(curl -s https://raw.githubusercontent.com/pry0cc/axiom/master/interact/axiom-configure)
                    """

    #Check if Axiom is installed upon instance being initiated, raise an error if not.
    def __init__(self):
        if not which('axiom-ls'):
            raise FileNotFoundError(dedent(self.ERROR_MESSAGE))
#----------------------------------------------------------------------------------------------------------------------------------#
    #Error handling wrapper.
    def handle(process):
        @wraps(process)
        def handler(self, *args, **kwargs):
            completed_process = process(self, *args, **kwargs)
            if completed_process.stderr:
                raise ChildProcessError(completed_process.stderr)
            else:
                return completed_process
        return handler
#----------------------------------------------------------------------------------------------------------------------------------#
    #Silencer to optionally supress command line output.
    def silence(method):
        @wraps(method)
        def silencer(self, *args, **kwargs):
            cmd = method(self, *args, **kwargs)
            if kwargs:
                return run(cmd, stdout=PIPE, stderr=PIPE)
            else:
                return run(cmd)
        return silencer
#----------------------------------------------------------------------------------------------------------------------------------#
    #Run 'axiom-ls' shell command to view running Axiom instances.
    @handle
    @silence
    def ls(self, silent=False):
        return ['axiom-ls']
#----------------------------------------------------------------------------------------------------------------------------------#
    #Run 'axiom-fleet' shell command to create an Axiom fleet. Provide the name of the fleet and number of desired instances.
    @handle
    @silence
    def fleet(self, name, instances, silent=False):
        return ['axiom-fleet', str(name), '-i', str(instances)]
#----------------------------------------------------------------------------------------------------------------------------------#
    #Run 'axiom-select' shell command to select desired Axiom instances. Provide a name to select and wildcard option that automatically appends '\*' to the name supplied.
    @handle
    @silence
    def select(self, name, wildcard=False, silent=False):
        return ['axiom-select', str(name) + '\*' if wildcard else str(name)]
 #----------------------------------------------------------------------------------------------------------------------------------#   
    #Run 'axiom-scan' shell command to execute an Axiom scan. Supply the path to the input file, the module name, and optionally: an output path, a maximum runtime, or a raw string to append to the command and pass to the shell.
    @handle
    @silence
    def scan(self, input, module, wordlist=None, output_path=None, runtime=None, raw=None, silent=False):
        args = ['axiom-scan', str(input), '-m', str(module)]
        if wordlist:
            args.extend(['-wL', str(wordlist)])
        if output_path: 
            args.extend(['-o', str(output_path)])
        if runtime: 
            args.extend(['--max-runtime', str(runtime)])
        if raw: 
            args.extend(split(raw))
        return args
#----------------------------------------------------------------------------------------------------------------------------------#
    #Run 'axiom-rm' shell command to delete Axiom instances. Provide a name to delete and a wildcard option that appends '\*' to the name provided.
    @handle
    @silence
    def rm(self, name, wildcard=False, silent=False):
        return ['axiom-rm', name + '0\*' if wildcard else name]
#----------------------------------------------------------------------------------------------------------------------------------#