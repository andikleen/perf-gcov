#define BACKTRACE_DISC
#include <backtrace.h>
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>
#include <stdio.h>

static void
error_callback (void *data, const char *msg, int errnum)
{
  fprintf (stderr, "libbacktrace error: %s, %d\n", msg, errnum);
}

static PyObject *
createstate (PyObject *self, PyObject *args)
{
  const char *filename;
  struct backtrace_state *state;
  if (!PyArg_ParseTuple (args, "s", &filename))
    return NULL;
  filename = strdup (filename);
  if (!filename)
    return PyErr_NoMemory ();
  state = backtrace_create_state (filename, 0, error_callback, NULL);
  if (!state)
    {
      free ((void *)filename);
      return NULL;
    }
  return PyCapsule_New (state, "backtrace_state", NULL);
}

static int
add_inlines (void *data, uintptr_t pc, const char *filename,
	    int lineno, const char *function, int disc)
{
  PyObject *list = (PyObject *) data;
  PyList_Append (list, Py_BuildValue ("Ksisi",
				      (unsigned long long) pc,
				      strdup (filename), lineno,
				      strdup (function), disc));
  return 0;
}

static PyObject *
pcinfo (PyObject *self, PyObject *args)
{
  PyObject *state_cap;
  PyObject *inline_list = PyList_New (0);
  struct backtrace_state *state;
  unsigned long long pc;
  if (!inline_list)
    return NULL;
  if (!PyArg_ParseTuple (args, "OK", &state_cap, &pc))
    return NULL;
  state = PyCapsule_GetPointer (state_cap, "backtrace_state");
  if (!state)
    return NULL;
  if (backtrace_pcinfo
      (state, pc, add_inlines, error_callback, inline_list))
    {
      Py_DECREF (inline_list);
      return NULL;
    }
  return inline_list;
}

static PyMethodDef backtrace_methods[] = {
  { "createstate", createstate, METH_VARARGS,
   "Initialize state for ELF file FILENAME" },
  { "pcinfo", pcinfo, METH_VARARGS,
   "Generate inline stack for STATE at IP. Returns list of (...) tuples" },
  { }
};

static struct PyModuleDef backtrace_module = {
  PyModuleDef_HEAD_INIT,
  "backtrace",
  NULL,
  -1,
  backtrace_methods
};

PyMODINIT_FUNC
PyInit_backtrace (void)
{
  return PyModule_Create (&backtrace_module);
}
