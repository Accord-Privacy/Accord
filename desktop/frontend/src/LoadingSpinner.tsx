export function LoadingSpinner() {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: "2rem",
    }}>
      <div style={{
        width: 24,
        height: 24,
        border: "3px solid rgba(255,255,255,0.2)",
        borderTopColor: "#7289da",
        borderRadius: "50%",
        animation: "spin 0.6s linear infinite",
      }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
