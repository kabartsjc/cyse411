// vulnerable: dangerouslySetInnerHTML
function Comment({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
