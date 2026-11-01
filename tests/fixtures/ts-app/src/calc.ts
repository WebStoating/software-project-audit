export function calculate(input: string): unknown {
  // planted: eval on caller-supplied input
  return eval(input);
}
