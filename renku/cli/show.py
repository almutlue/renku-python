# -*- coding: utf-8 -*-
#
# Copyright 2018-2021- Swiss Data Science Center (SDSC)
# A partnership between École Polytechnique Fédérale de Lausanne (EPFL) and
# Eidgenössische Technische Hochschule Zürich (ETHZ).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
r"""Show information about objects in current repository.

Siblings
~~~~~~~~

In situations when multiple outputs have been generated by a single
``renku run`` command, the siblings can be discovered by running
``renku show siblings PATH`` command.

Assume that the following graph represents relations in the repository.

.. code-block:: text

          D---E---G
         /     \
    A---B---C   F

Then the following outputs would be shown.

.. code-block:: console

   $ renku show siblings C
   C
   D
   $ renku show siblings G
   F
   G
   $ renku show siblings A
   A
   $ renku show siblings C G
   C
   D
   ---
   F
   G
   $ renku show siblings
   A
   ---
   B
   ---
   C
   D
   ---
   E
   ---
   F
   G

You can use the ``-f`` or ``--flat`` flag to output a flat list, as well as
the ``-v`` or ``--verbose`` flag to also output commit information.


Input and output files
~~~~~~~~~~~~~~~~~~~~~~

You can list input and output files generated in the repository by running
``renku show inputs`` and ``renku show outputs`` commands. Alternatively,
you can check if all paths specified as arguments are input or output files
respectively.

.. code-block:: console

   $ renku run wc < source.txt > result.wc
   $ renku show inputs
   source.txt
   $ renku show outputs
   result.wc
   $ renku show outputs source.txt
   $ echo $?  # last command finished with an error code
   1

You can use the ``-v`` or ``--verbose`` flag to print detailed information
in a tabular format.

.. code-block:: console

   $ renku show inputs -v
   PATH        COMMIT   USAGE TIME           WORKFLOW
   ----------  -------  -------------------  -------------------...-----------
   source.txt  6d10e05  2020-09-14 23:47:17  .renku/workflow/388...d8_head.yaml


"""
from collections import namedtuple

import click

from renku.cli.utils.callback import ClickCallback
from renku.core.commands.show import get_inputs, get_outputs, get_siblings
from renku.core.models.tabulate import tabulate

Result = namedtuple("Result", ["path", "commit", "time", "workflow"])
HEADERS = {"path": None, "commit": None, "time": "time", "workflow": None}


@click.group()
def show():
    """Show information about objects in a current repository.

    NOTE: The command produces a machine-readable output.
    """


@show.command()
@click.option("--revision", default="HEAD")
@click.option("-f", "--flat", is_flag=True)
@click.option("-v", "--verbose", is_flag=True)
@click.argument("paths", type=click.Path(exists=True, dir_okay=False), nargs=-1)
def siblings(revision, flat, verbose, paths):
    """Show siblings for given paths."""
    communicator = ClickCallback()

    result = (
        get_siblings().with_communicator(communicator).build().execute(revision=revision, verbose=verbose, paths=paths)
    )
    result = result.output

    if flat:
        click.echo("\n".join({n for r in result for n in r}))
    else:
        click.echo("\n---\n".join("\n".join(r) for r in result))


@show.command()
@click.option("--revision", default="HEAD")
@click.option("-v", "--verbose", is_flag=True)
@click.argument("paths", type=click.Path(exists=True, dir_okay=False), nargs=-1)
@click.pass_context
def inputs(ctx, revision, verbose, paths):
    r"""Show inputs files in the repository.

    <PATHS>    Files to show. If no files are given all input files are shown.
    """
    communicator = ClickCallback()

    result = get_inputs().with_communicator(communicator).build().execute(revision=revision, paths=paths)
    input_paths = result.output

    if not verbose:
        click.echo("\n".join(input_paths.keys()))
    else:
        records = list(input_paths.values())
        records.sort(key=lambda v: v[0])
        HEADERS["time"] = "usage time"
        click.echo(tabulate(collection=records, headers=HEADERS))

    ctx.exit(0 if not paths or len(input_paths) == len(paths) else 1)


@show.command()
@click.option("--revision", default="HEAD")
@click.option("-v", "--verbose", is_flag=True)
@click.argument("paths", type=click.Path(exists=True, dir_okay=True), nargs=-1)
@click.pass_context
def outputs(ctx, revision, verbose, paths):
    r"""Show output files in the repository.

    <PATHS>    Files to show. If no files are given all output files are shown.
    """
    communicator = ClickCallback()

    result = get_outputs().with_communicator(communicator).build().execute(revision=revision, paths=paths)
    filter_, output_paths = result.output

    if not verbose:
        click.echo("\n".join(output_paths.keys()))
    else:
        records = list(output_paths.values())
        records.sort(key=lambda v: v[0])
        HEADERS["time"] = "generation time"
        click.echo(tabulate(collection=records, headers=HEADERS))

    if paths:
        if not output_paths:
            ctx.exit(1)

        from renku.core.models.datastructures import DirectoryTree

        tree = DirectoryTree.from_list(item.path for item in filter_)

        for output in output_paths:
            if tree.get(output) is None:
                ctx.exit(1)
                return
