# command_registry.py — shared handles that commands operate on
_registry = {}

def register(name, obj):
    _registry[name] = obj

def get_handler(name):
    return _registry.get(name)