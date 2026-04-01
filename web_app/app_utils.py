import logging

logger = logging.getLogger(__name__)

def check_if_stopped(stop_requested):
    """Check if the operation should be stopped"""
    if stop_requested:
        logger.info("Operation stopped by user request")
        raise InterruptedError("Operation stopped by user request")
