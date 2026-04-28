import { io } from "socket.io-client";

const socket = io("http://localhost:5001", {
  autoConnect: false,
  transports: ["websocket"],   // skip polling — shows cleanly as WS in DevTools
});
export default socket;
