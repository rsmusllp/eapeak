::

    ::::::::::     :::     :::::::::  ::::::::::     :::     :::    :::
    :+:          :+: :+:   :+:    :+: :+:          :+: :+:   :+:   :+:  
    +:+         +:+   +:+  +:+    +:+ +:+         +:+   +:+  +:+  +:+   
    +#++:++#   +#++:++#++: +#++:++#+  +#++:++#   +#++:++#++: +#++:++    
    +#+        +#+     +#+ +#+        +#+        +#+     +#+ +#+  +#+   
    #+#        #+#     #+# #+#        #+#        #+#     #+# #+#   #+#  
    ########## ###     ### ###        ########## ###     ### ###    ###

Summary
=======

EAPeak is a suite of open source tools to facilitate auditing of wireless
networks that utilize the Extensible Authentication Protocol framework for
authentication. It is meant to give useful information relating to the security
of these networks for pentesters to use while searching for vulnerabilities.

License
=======

EAPeak is released under the BSD 3-clause license, for more details see
the `LICENSE <https://github.com/securestate/eapeak/blob/master/LICENSE>`__
file.

About
=====

Author: Spencer McIntyre - zeroSteiner
(`@zeroSteiner <https://twitter.com/zeroSteiner>`__)

Install
=======

EAPeak uses `pipenv <https://docs.pipenv.org/>`__ to manage it's dependencies
and environment.

#. If ``pipenv`` is not already installed, use ``pip`` to install it.

   * ``sudo pip install pipenv``

#. Clone the EAPeak repository from GitHub and change directories into it.

   * ``git clone https://github.com/securestate/eapeak``
   * ``cd eapeak``

#. Install the environment and dependencies (this may take a while).

   * ``pipenv --two install``

#. Start a pipenv shell to use EAPeak.

   * ``pipenv shell``

**Note:** If EAPeak must be run as root (as is required for live capturing or
injection), then steps 3 and 4 must also be run as the root user. It is
recommended to do so from an interactive shell as the root user (using ``su`` or
``sudo -i`` as opposed to simply using ``sudo``.
