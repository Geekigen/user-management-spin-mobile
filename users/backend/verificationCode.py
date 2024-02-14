import random


def generateCode():
    return ''.join(str(random.randint(0, 9)) for _ in range(6))


# print(generateCode())
