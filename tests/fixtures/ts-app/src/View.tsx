export function View(props: { html: string }) {
  // planted: unsanitized HTML injection
  return <div dangerouslySetInnerHTML={{ __html: props.html }} />;
}
