# -*- coding: utf-8 -*-
#
# Copyright 2018 - Swiss Data Science Center (SDSC)
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
"""Represent a ``CommandLineTool`` from the Common Workflow Language."""

import fnmatch
import re
import shlex
from contextlib import contextmanager

import attr

from renga._compat import Path

from ._ascwl import CWLClass, mapped
from .parameter import CommandInputParameter, CommandLineBinding, \
    CommandOutputParameter
from .process import Process
from .types import File


@attr.s
class CommandLineTool(Process, CWLClass):
    """Represent a command line tool."""

    # specialize inputs and outputs with Command{Input,Output}Parameter

    baseCommand = attr.ib(
        default='',
        validator=lambda self, attr, cmd: bool(cmd),
    )  # str or list(str) -> shutil.split()
    arguments = attr.ib(
        default=attr.Factory(list),
        converter=lambda cmd: list(cmd) if isinstance(
            cmd, (list, tuple)) else shlex.split(cmd),
    )  # list(string, Expression, CommandLineBinding)

    stdin = attr.ib(default=None)
    stdout = attr.ib(default=None)
    stderr = attr.ib(default=None)

    inputs = mapped(CommandInputParameter)
    outputs = mapped(CommandOutputParameter)

    successCodes = attr.ib(default=attr.Factory(list))  # list(int)
    temporaryFailCodes = attr.ib(default=attr.Factory(list))  # list(int)
    permanentFailCodes = attr.ib(default=attr.Factory(list))  # list(int)

    def get_output_id(self, path):
        """Return an id of the matching path from default values."""
        for output in self.outputs:
            if output.type in {'stdout', 'stderr'}:
                stream = getattr(self, output.type)
                if stream == path:
                    return output.id
            elif output.type == 'File':
                glob = output.outputBinding.glob
                # TODO better support for Expression
                if glob.startswith('$(inputs.'):
                    input_id = glob[len('$(inputs.'):-1]
                    for input_ in self.inputs:
                        if input_.id == input_id and input_.default == path:
                            return output.id
                elif fnmatch.fnmatch(path, glob):
                    return output.id


@attr.s
class CommandLineToolFactory(object):
    """Command Line Tool Factory."""

    _RE_SUBCOMMAND = re.compile(r'^[A-Za-z]+(-[A-Za-z]+)?$')

    command_line = attr.ib(
        converter=lambda cmd: list(cmd) if isinstance(
            cmd, (list, tuple)) else shlex.split(cmd),

    )

    directory = attr.ib(
        default='.',
        converter=Path,
    )

    stdin = attr.ib(default=None)  # null, str, Expression
    stderr = attr.ib(default=None)  # null, str, Expression
    stdout = attr.ib(default=None)  # null, str, Expression

    baseCommand = attr.ib(init=False)
    arguments = attr.ib(init=False)
    inputs = attr.ib(init=False)
    outputs = attr.ib(init=False)

    def __attrs_post_init__(self):
        """Derive basic informations."""
        self.baseCommand, detect = self.split_command_and_args()
        self.arguments = []
        self.inputs = []
        self.outputs = []

        if self.stdin:
            input_ = next(self.guess_inputs(self.stdin))
            assert input_.type == 'File'
            input_.id = 'input_stdin'
            self.inputs.append(input_)
            self.stdin = '$(inputs.{0}.path)'.format(input_.id)

        for stream_name in ('stdout', 'stderr'):
            stream = getattr(self, stream_name)
            if stream and self.file_candidate(stream):
                self.outputs.append(
                    CommandOutputParameter(
                        id='output_{0}'.format(stream_name),
                        type=stream_name,
                    ))

        for input_ in self.guess_inputs(*detect):
            if isinstance(input_, CommandLineBinding):
                self.arguments.append(input_)
            else:
                self.inputs.append(input_)

    def generate_tool(self):
        """Return an instance of command line tool."""
        return CommandLineTool(
            stdin=self.stdin,
            stderr=self.stderr,
            stdout=self.stdout,
            baseCommand=self.baseCommand,
            arguments=self.arguments,
            inputs=self.inputs,
            outputs=self.outputs,
        )

    @contextmanager
    def watch(self, repo=None, no_output=False):
        """Watch a git repository for changes to detect outputs."""
        tool = self.generate_tool()
        git = repo.git

        yield tool

        if git:
            candidates = set(git.untracked_files)
            candidates |= {item.a_path for item in git.index.diff(None)}

            inputs = {input.id: input for input in self.inputs}
            outputs = list(tool.outputs)
            lfs_paths = []

            for output, input, path in self.guess_outputs(candidates):
                outputs.append(output)
                lfs_paths.append(path)

                if input is not None:
                    if input.id not in inputs:  # pragma: no cover
                        raise RuntimeError('Inconsistent input name.')

                    inputs[input.id] = input

            if not no_output:
                for stream_name in ('stdout', 'stderr'):
                    stream = getattr(self, stream_name)
                    if stream and stream not in candidates:
                        raise RuntimeError(
                            'Output file was not created or changed.'
                        )
                    elif stream:
                        lfs_paths.append(stream)

                if not outputs:
                    raise RuntimeError('No output was detected')

            tool.inputs = list(inputs.values())
            tool.outputs = outputs
            repo.track_lfs_paths(lfs_paths)

    @command_line.validator
    def validate_command_line(self, attribute, value):
        """Check the command line structure."""
        if not value:
            raise ValueError('Command line can not be empty.')

    @directory.validator
    def validate_path(self, attribute, value):
        """Path must exists."""
        if not value.exists():
            raise ValueError('Directory must exist.')

    def file_candidate(self, candidate):
        """Return a path instance if it exists in current directory."""
        candidate = Path(candidate)

        if not candidate.is_absolute():
            candidate = self.directory / candidate

        if candidate.exists():
            return candidate

    def split_command_and_args(self):
        """Return tuple with command and args from command line arguments."""
        cmd = [self.command_line[0]]
        args = list(self.command_line[1:])

        if len(args) < 2:
            # only guess subcommand for more arguments
            return cmd, args

        while args and re.match(self._RE_SUBCOMMAND, args[0]) \
                and not self.file_candidate(args[0]):
            cmd.append(args.pop(0))

        return cmd, args

    def guess_type(self, value):
        """Return new value and CWL parameter type."""
        try:
            value = int(value)
            return value, 'int', None
        except ValueError:
            pass

        candidate = self.file_candidate(value)
        if candidate:
            try:
                return File(
                    path=candidate.relative_to(self.directory)
                ), 'File', None
            except ValueError:
                # The candidate points to a file outside the working
                # directory
                # TODO suggest that the file should be imported to the repo
                pass

        if len(value) > 1 and ',' in value:
            return value.split(','), 'string[]', ','

        return value, 'string', None

    def guess_inputs(self, *arguments):
        """Yield command input parameters and command line bindings."""
        position = 0
        prefix = None

        for index, argument in enumerate(arguments):
            itemSeparator = None

            if prefix:
                if argument.startswith('-'):
                    position += 1
                    yield CommandLineBinding(
                        position=position,
                        prefix=prefix,
                    )
                    prefix = None

            if argument.startswith('--'):
                if '=' in argument:
                    prefix, default = argument.split('=', 1)
                    prefix += '='
                    default, type, itemSeparator = self.guess_type(default)
                    # TODO can be output

                    position += 1
                    yield CommandInputParameter(
                        id='input_{0}'.format(position),
                        type=type,
                        default=default,
                        inputBinding=dict(
                            position=position,
                            itemSeparator=itemSeparator,
                            prefix=prefix,
                            separate=False,
                        ))
                    prefix = None
                else:
                    prefix = argument

            elif argument.startswith('-'):
                if len(argument) > 2:
                    if '=' in argument:
                        prefix, default = argument.split('=', 1)
                        prefix += '='
                        default, type, itemSeparator = self.guess_type(default)
                    else:
                        # possibly a flag with value
                        prefix = argument[0:2]
                        default, type, itemSeparator = self.guess_type(
                            argument[2:])

                    position += 1
                    yield CommandInputParameter(
                        id='input_{0}'.format(position),
                        type=type,
                        default=default,
                        inputBinding=dict(
                            position=position,
                            itemSeparator=itemSeparator,
                            prefix=prefix,
                            separate=not bool(argument[2:]),
                        ))
                    prefix = None
                else:
                    prefix = argument

            else:
                default, type, itemSeparator = self.guess_type(argument)
                # TODO can be output

                # TODO there might be an array
                position += 1
                yield CommandInputParameter(
                    id='input_{0}'.format(position),
                    type=type,
                    default=default,
                    inputBinding=dict(
                        position=position,
                        itemSeparator=itemSeparator,
                        prefix=prefix,
                    ))
                prefix = None

        if prefix:
            position += 1
            yield CommandLineBinding(
                position=position,
                prefix=prefix,
            )

    def guess_outputs(self, paths):
        """Yield detected output and changed command input parameter."""
        input_candidates = {
            str(input.default): input
            for input in self.inputs if input.type != 'File'
        }  # inputs that need to be changed if an output is detected

        conflicting_paths = {
            str(input.default)
            for input in self.inputs if input.type == 'File'
        }  # names that can not be outputs because they are already inputs

        streams = {path for path in (
            getattr(self, name) for name in ('stdout', 'stderr')
        ) if path is not None}

        # TODO group by a common prefix

        for position, path in enumerate(paths):
            candidate = self.file_candidate(path)

            if candidate is None:
                raise ValueError('Path "{0}" does not exist.'.format(path))

            glob = str(candidate.relative_to(self.directory))

            if glob in streams:
                continue

            if glob in conflicting_paths:
                raise ValueError('Output already exists in inputs.')

            if glob in input_candidates:
                input = input_candidates[glob]
                if input.type == 'File':
                    # it means that it is rewriting a file
                    raise NotImplemented()

                yield (CommandOutputParameter(
                    id='output_{0}'.format(position),
                    type='File',
                    outputBinding=dict(
                        glob='$(inputs.{0})'.format(input.id), ),
                ), None, path)
            else:
                yield (CommandOutputParameter(
                    id='output_{0}'.format(position),
                    type='File',
                    outputBinding=dict(glob=glob, ),
                ), None, path)
