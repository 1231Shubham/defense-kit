"""
modules package — plugin-shaped scan/audit modules.

Each file here that defines a MODULE_META dict and a run(config,
session_id) function is auto-discovered by utils/module_loader.py and
added to both the interactive menu and (if it also defines
cli_run(args, session_id)) the --module CLI options.

An explicit __init__.py (rather than relying on Python 3's implicit
namespace packages) keeps `import modules` and pkgutil.iter_modules()
behavior predictable regardless of how the toolkit is packaged/run —
namespace packages can behave surprisingly if another "modules"
directory ever ends up earlier on sys.path.
"""
