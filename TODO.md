# Cloak TODO List

## Security and Permissions

- [ ] Make crypto key files only readable by the user who created them (needs testing).
- [ ] Make output files retain the same permissions as the input files that generated them.
- [x] Restore minimum password length enforcement for `pswgen -l <L>` and input validation.

## Performance

- [ ] Improve memory handling for large files to reduce RAM usage during operations.

## Quality of Life

- [x] Implement detection of execution in non-interactive terminals and react accordingly (overwrite confirmation, password input, etc.).
