export const UserRoleEnum = {
  ADMIN: "admin",
  PROJECT_ADMIN: "project_admin",
  MEMBER: "member",
};
export const AvaiableUserRoles = Object.values(UserRoleEnum);
export const TaskStatusEnum = {
  TODO : "todo",
  PRIORITY: "priority",
  IN_PROGRESS: "in_progress",
  IN_REVIEW: "in_review",
  CANCELLED: "cancelled",
  DONE: " done",
};
export const AvaiableTaskStatus = Object.values(TaskStatusEnum);
export const TaskPrioritiesEnum = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
};
export const AvaiableTaskPrioriorties = Object.values(TaskPrioritiesEnum);
