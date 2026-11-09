"""TEST-ONLY stand-in for Celery, used when Celery is not installed. It mimics the small part of the API this
project uses: Celery(...), app.conf, @app.task(...), task.delay(...), task.apply_async(...). Tasks run immediately."""
import types


class _Task:
    def __init__(self, fn, bind=False):
        self.fn, self.bind, self.calls = fn, bind, []
        self.__name__ = fn.__name__

    def __call__(self, *a, **k):
        return self.fn(self, *a, **k) if self.bind else self.fn(*a, **k)

    def delay(self, *a, **k):
        self.calls.append((a, k))
        return types.SimpleNamespace(result=self(*a, **k), id="fake")

    def apply_async(self, args=(), kwargs=None, **opts):
        return self.delay(*args, **(kwargs or {}))

    def retry(self, exc=None, **kw):
        raise exc or RuntimeError("retry")


class Celery:
    def __init__(self, name=None, broker=None, backend=None, **kw):
        self.main, self.broker, self.backend = name, broker, backend
        self.conf = types.SimpleNamespace(update=lambda **k: self.conf.__dict__.update(k))

    def task(self, *dargs, **opts):
        def deco(fn):
            return _Task(fn, bind=opts.get("bind", False))
        return deco(dargs[0]) if dargs and callable(dargs[0]) else deco
