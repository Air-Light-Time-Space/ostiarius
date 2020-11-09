version_number = (0, 1)
version = "ostiarius-kpdfw-v{:d}.{:d}".format(version_number[0], version_number[1])

if __name__ == '__main__':
    # If we get here it means our main loop crashed (in boot.py). Let's just reset and hope it doesn't happen again ;)
    import machine
    from configuration import Configuration
    config = Configuration('config')

    if not config.DEBUG:
        machine.reset()
