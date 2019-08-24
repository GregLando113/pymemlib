from ctypes import (
    c_char as CHAR
)

def create_buffer(size):
    """Create a ctypes buffer of a given size."""
    buftype = CHAR * size
    return buftype()

def get_ctype_string(type):
    """Returns the type string to be used with unpack/pack"""
    from ctypes import _SimpleCData

    if issubclass(type, _SimpleCData):
        return type._type_
    elif issubclass(type, Array):
        elem_type = _get_ctype_string(type._type_)
        return "%d%s" % (type._length_, elem_type)
    elif issubclass(type, Structure):
        return "".join(_get_ctype_string(t) for n, t in type._fields_)
    else:
        raise RuntimeError("The type %s is not supported" % str(type))