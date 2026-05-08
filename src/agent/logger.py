import logging


class Logger:
    _is_configured = False

    @classmethod
    def _setup(cls):
        if cls._is_configured:
            return
        

        logging.basicConfig(
            level  = logging.INFO,
            format = "%(asctime)s [%(name)s] %(levelname)s %(message)s",
            datefmt= "%Y-%m-%dT%H:%M:%S",
        )

        cls._is_configured = True

    
    @classmethod
    def get_logger(cls , name:str):
        cls._setup()
        return logging.getLogger(name)
