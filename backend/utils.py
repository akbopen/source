# Helper functions

def passmein(func):
    def wrapper(*args, **kwargs):
        print(f'{args}, {kwargs}, {func}')
        return func(*args, **kwargs)
    print(f'{wrapper}')

    return wrapper
