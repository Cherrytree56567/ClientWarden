mod nav_panel;

use nav_panel::{NavPanel, Page};

use iced::widget::{column, container, row, text, button};
use iced::{Element, Task, Theme, Color, Length};
use iced::theme::Palette;

fn main() -> iced::Result {
    iced::application(App::new, App::update, App::view)
        .title(App::title)
        .theme(App::theme)
        .window_size((700.0, 400.0))
        .run()
}

struct App {
    navPanel: NavPanel,
}

#[derive(Debug, Clone)]
enum Message {
    NavPanel(nav_panel::Message),
}

impl App {
    fn new() -> (Self, Task<Message>) {
        (
            Self {
                navPanel: NavPanel::new()
            },
            Task::none(),
        )
    }

    fn title(&self) -> String {
        "Clientwarden".to_string()
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::NavPanel(msg) => {
                self.navPanel.update(msg);
            }
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let nav = self.navPanel.view().map(Message::NavPanel);

        row![
            container(nav).padding(10).height(Length::Fill),
        ]
        .into()
    }

    fn theme(&self) -> Theme {
        Theme::custom(
            "Catppuccin".to_string(),
            Palette {
                background: Color::from_rgb8(17, 17, 27),
                text: Color::from_rgb8(205, 214, 244),
                primary: Color::from_rgb8(137, 180, 250),
                success: Color::from_rgb8(166, 227, 161),
                warning: Color::from_rgb8(249, 226, 175),
                danger: Color::from_rgb8(243, 139, 168),
            },
        )
    }
}