from aurorastack.core.manager import BaseManager

__all__ = ['HelloWorldManager']


class HelloWorldManager(BaseManager):

    def say_hello(self, name):
        return f'Hello, {name}!'
