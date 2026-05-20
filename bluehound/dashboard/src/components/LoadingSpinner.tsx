export default function LoadingSpinner() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-dark-900">
      <div className="text-center animate-fade-in">
        <div className="relative inline-block mb-6">
          <div className="w-16 h-16 rounded-full border-4 border-dark-700" />
          <div className="w-16 h-16 rounded-full border-4 border-primary-500 border-t-transparent animate-spin absolute inset-0" />
        </div>
        <p className="text-gray-400 text-sm tracking-wide">Loading threat model data…</p>
      </div>
    </div>
  );
}
