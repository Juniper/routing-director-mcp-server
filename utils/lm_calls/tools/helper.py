from utils.lm_calls.paragon.constants import EOP_HOST


def get_full_eop_host():
    """
    Ensures EOP_HOST has 'http://' or 'https://' prefix based on deployment.
    If not present, 'https://' is added by default.
    """

    if not (EOP_HOST.startswith('http://') or EOP_HOST.startswith('https://')):
        return f'https://{EOP_HOST}'

    return EOP_HOST